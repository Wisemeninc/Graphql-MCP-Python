"""
GraphQL MCP Server with Streamable HTTP Transport
Implements the MCP protocol over HTTP with SSE support for VS Code integration
"""

import os
import json
import logging
import asyncio
import uuid
import secrets
import hashlib
import time
from typing import Any, Optional
from urllib.parse import urlencode
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, RedirectResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sse_starlette.sse import EventSourceResponse
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import get_introspection_query, build_client_schema, print_schema
from dotenv import load_dotenv
import uvicorn
import aiohttp

# Import version info
try:
    from version import __version__, MCP_PROTOCOL_VERSION, SERVER_NAME
except ImportError:
    __version__ = "1.0.0"
    MCP_PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "graphql-mcp-server"

# Load environment variables
load_dotenv()

# Configure logging with debug support
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Set third-party loggers to WARNING to reduce noise
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)

# Server info
SERVER_VERSION = __version__
PROTOCOL_VERSION = MCP_PROTOCOL_VERSION

# GitHub OAuth Configuration
GITHUB_AUTH_ENABLED = os.getenv("GITHUB_AUTH_ENABLED", "false").lower() == "true"
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_ALLOWED_USERS = [u.strip() for u in os.getenv("GITHUB_ALLOWED_USERS", "").split(",") if u.strip()]
GITHUB_ALLOWED_ORGS = [o.strip() for o in os.getenv("GITHUB_ALLOWED_ORGS", "").split(",") if o.strip()]
GITHUB_OAUTH_CALLBACK_URL = os.getenv("GITHUB_OAUTH_CALLBACK_URL", "")
AUTH_TOKEN_EXPIRY = int(os.getenv("AUTH_TOKEN_EXPIRY", "86400"))  # Default 24 hours

# Token storage (in production, use Redis or database)
oauth_states: dict[str, dict] = {}  # state -> {created_at, redirect_uri}
auth_tokens: dict[str, dict] = {}  # token -> {user, orgs, created_at, expires_at}

# Global GraphQL client
graphql_client = None

# Store for SSE connections and pending responses
sse_connections: dict[str, asyncio.Queue] = {}


def get_graphql_client() -> Client:
    """Get or create GraphQL client"""
    global graphql_client
    
    if graphql_client is None:
        endpoint = os.getenv("GRAPHQL_ENDPOINT")
        if not endpoint:
            logger.error("GRAPHQL_ENDPOINT environment variable is not set")
            raise ValueError("GRAPHQL_ENDPOINT environment variable is required")
        
        logger.debug(f"Creating GraphQL client for endpoint: {endpoint}")
        
        headers = {}
        auth_token = os.getenv("GRAPHQL_AUTH_TOKEN")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
            logger.debug("Added Bearer token authentication")
        
        custom_headers = os.getenv("GRAPHQL_HEADERS")
        if custom_headers:
            try:
                headers.update(json.loads(custom_headers))
                logger.debug(f"Added custom headers: {list(json.loads(custom_headers).keys())}")
            except json.JSONDecodeError:
                logger.warning("Invalid GRAPHQL_HEADERS format, skipping")
        
        logger.debug(f"Final headers (keys only): {list(headers.keys())}")
        transport = AIOHTTPTransport(url=endpoint, headers=headers)
        graphql_client = Client(transport=transport, fetch_schema_from_transport=False)
        logger.info(f"GraphQL client initialized for: {endpoint}")
    
    return graphql_client


# ============================================================================
# GitHub OAuth Authentication
# ============================================================================

def generate_oauth_state() -> str:
    """Generate a secure random state for OAuth"""
    return secrets.token_urlsafe(32)


def generate_auth_token() -> str:
    """Generate a secure authentication token"""
    return secrets.token_urlsafe(64)


def cleanup_expired_tokens():
    """Remove expired tokens and states"""
    current_time = time.time()
    
    # Clean up expired states (5 minute expiry)
    expired_states = [s for s, data in oauth_states.items() 
                      if current_time - data["created_at"] > 300]
    for state in expired_states:
        oauth_states.pop(state, None)
    
    # Clean up expired tokens
    expired_tokens = [t for t, data in auth_tokens.items() 
                      if current_time > data["expires_at"]]
    for token in expired_tokens:
        auth_tokens.pop(token, None)
        logger.debug(f"Removed expired auth token")


def validate_auth_token(token: str) -> Optional[dict]:
    """Validate an authentication token and return user info if valid"""
    cleanup_expired_tokens()
    
    if not token:
        return None
    
    # Remove 'Bearer ' prefix if present
    if token.startswith("Bearer "):
        token = token[7:]
    
    token_data = auth_tokens.get(token)
    if not token_data:
        return None
    
    if time.time() > token_data["expires_at"]:
        auth_tokens.pop(token, None)
        return None
    
    return token_data


def is_user_authorized(user_data: dict) -> bool:
    """Check if a user is authorized based on username or org membership"""
    username = user_data.get("user", "")
    user_orgs = user_data.get("orgs", [])
    
    # If no restrictions configured, allow all authenticated users
    if not GITHUB_ALLOWED_USERS and not GITHUB_ALLOWED_ORGS:
        return True
    
    # Check username
    if username in GITHUB_ALLOWED_USERS:
        logger.debug(f"User {username} authorized via username allowlist")
        return True
    
    # Check org membership
    for org in user_orgs:
        if org in GITHUB_ALLOWED_ORGS:
            logger.debug(f"User {username} authorized via org {org}")
            return True
    
    logger.warning(f"User {username} not in allowed users or orgs")
    return False


async def fetch_github_user(access_token: str) -> Optional[dict]:
    """Fetch GitHub user info using access token"""
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            # Get user info
            async with session.get("https://api.github.com/user", headers=headers) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to fetch GitHub user: {resp.status}")
                    return None
                user_info = await resp.json()
            
            # Get user's organizations
            async with session.get("https://api.github.com/user/orgs", headers=headers) as resp:
                if resp.status == 200:
                    orgs_info = await resp.json()
                    orgs = [org["login"] for org in orgs_info]
                else:
                    orgs = []
            
            return {
                "login": user_info.get("login"),
                "id": user_info.get("id"),
                "name": user_info.get("name"),
                "email": user_info.get("email"),
                "avatar_url": user_info.get("avatar_url"),
                "orgs": orgs
            }
    except Exception as e:
        logger.error(f"Error fetching GitHub user: {e}", exc_info=True)
        return None


async def exchange_code_for_token(code: str) -> Optional[str]:
    """Exchange OAuth code for access token"""
    try:
        async with aiohttp.ClientSession() as session:
            data = {
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code
            }
            headers = {"Accept": "application/json"}
            
            async with session.post(
                "https://github.com/login/oauth/access_token",
                data=data,
                headers=headers
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to exchange code: {resp.status}")
                    return None
                
                result = await resp.json()
                if "error" in result:
                    logger.error(f"OAuth error: {result.get('error_description', result['error'])}")
                    return None
                
                return result.get("access_token")
    except Exception as e:
        logger.error(f"Error exchanging OAuth code: {e}", exc_info=True)
        return None


class GitHubAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce GitHub OAuth authentication"""
    
    # Endpoints that don't require authentication
    PUBLIC_PATHS = {"/health", "/auth/login", "/auth/callback", "/auth/status"}
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth if not enabled
        if not GITHUB_AUTH_ENABLED:
            return await call_next(request)
        
        # Allow public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Check for auth token
        auth_header = request.headers.get("Authorization", "")
        token_data = validate_auth_token(auth_header)
        
        if not token_data:
            logger.debug(f"Unauthorized request to {request.url.path}")
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "message": "Valid authentication required. Visit /auth/login to authenticate.",
                    "login_url": "/auth/login"
                },
                status_code=401
            )
        
        # Check if user is authorized
        if not is_user_authorized(token_data):
            return JSONResponse(
                {
                    "error": "Forbidden",
                    "message": "User not authorized to access this server"
                },
                status_code=403
            )
        
        # Add user info to request state
        request.state.user = token_data
        return await call_next(request)


# OAuth Endpoints

async def auth_login(request: Request) -> Response:
    """Initiate GitHub OAuth login"""
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({"error": "GitHub authentication is not enabled"}, status_code=400)
    
    if not GITHUB_CLIENT_ID:
        return JSONResponse({"error": "GitHub OAuth not configured"}, status_code=500)
    
    # Generate state for CSRF protection
    state = generate_oauth_state()
    redirect_uri = request.query_params.get("redirect_uri", "")
    
    oauth_states[state] = {
        "created_at": time.time(),
        "redirect_uri": redirect_uri
    }
    
    # Build GitHub OAuth URL
    callback_url = GITHUB_OAUTH_CALLBACK_URL or str(request.url_for("auth_callback"))
    
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": callback_url,
        "scope": "read:user read:org",
        "state": state
    }
    
    github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    logger.info(f"Initiating OAuth login, state: {state[:8]}...")
    
    # Return JSON for API clients, redirect for browsers
    if "application/json" in request.headers.get("Accept", ""):
        return JSONResponse({
            "auth_url": github_auth_url,
            "state": state
        })
    
    return RedirectResponse(url=github_auth_url)


async def auth_callback(request: Request) -> Response:
    """Handle GitHub OAuth callback"""
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({"error": "GitHub authentication is not enabled"}, status_code=400)
    
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        logger.error(f"OAuth error: {error}")
        return JSONResponse({
            "error": "OAuth authentication failed",
            "details": request.query_params.get("error_description", error)
        }, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "Missing code or state parameter"}, status_code=400)
    
    # Validate state
    state_data = oauth_states.pop(state, None)
    if not state_data:
        return JSONResponse({"error": "Invalid or expired state"}, status_code=400)
    
    logger.debug(f"Processing OAuth callback for state: {state[:8]}...")
    
    # Exchange code for access token
    access_token = await exchange_code_for_token(code)
    if not access_token:
        return JSONResponse({"error": "Failed to exchange code for token"}, status_code=400)
    
    # Fetch user info
    user_info = await fetch_github_user(access_token)
    if not user_info:
        return JSONResponse({"error": "Failed to fetch user info"}, status_code=400)
    
    # Check authorization
    temp_user_data = {"user": user_info["login"], "orgs": user_info["orgs"]}
    if not is_user_authorized(temp_user_data):
        logger.warning(f"Unauthorized user attempted login: {user_info['login']}")
        return JSONResponse({
            "error": "Forbidden",
            "message": f"User {user_info['login']} is not authorized to access this server"
        }, status_code=403)
    
    # Generate auth token
    auth_token = generate_auth_token()
    expires_at = time.time() + AUTH_TOKEN_EXPIRY
    
    auth_tokens[auth_token] = {
        "user": user_info["login"],
        "user_id": user_info["id"],
        "name": user_info["name"],
        "email": user_info["email"],
        "orgs": user_info["orgs"],
        "created_at": time.time(),
        "expires_at": expires_at
    }
    
    logger.info(f"User {user_info['login']} authenticated successfully")
    
    # Check for redirect URI
    redirect_uri = state_data.get("redirect_uri")
    if redirect_uri:
        # Redirect with token as fragment (more secure than query param)
        return RedirectResponse(url=f"{redirect_uri}#token={auth_token}")
    
    return JSONResponse({
        "success": True,
        "token": auth_token,
        "user": user_info["login"],
        "expires_in": AUTH_TOKEN_EXPIRY,
        "message": "Use this token in the Authorization header: Bearer <token>"
    })


async def auth_status(request: Request) -> JSONResponse:
    """Check authentication status"""
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({
            "auth_enabled": False,
            "message": "GitHub authentication is not enabled"
        })
    
    auth_header = request.headers.get("Authorization", "")
    token_data = validate_auth_token(auth_header)
    
    if token_data:
        return JSONResponse({
            "auth_enabled": True,
            "authenticated": True,
            "user": token_data.get("user"),
            "expires_at": token_data.get("expires_at")
        })
    
    return JSONResponse({
        "auth_enabled": True,
        "authenticated": False,
        "login_url": "/auth/login"
    })


async def auth_logout(request: Request) -> JSONResponse:
    """Logout and invalidate token"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token in auth_tokens:
            user = auth_tokens[token].get("user", "unknown")
            auth_tokens.pop(token, None)
            logger.info(f"User {user} logged out")
            return JSONResponse({"success": True, "message": "Logged out successfully"})
    
    return JSONResponse({"success": True, "message": "No active session"})


# ============================================================================
# Tool definitions
# ============================================================================

def get_tools() -> list[dict]:
    """Get list of available tools"""
    return [
        {
            "name": "graphql_introspection",
            "description": "Perform GraphQL introspection to discover the schema, types, queries, mutations, and fields available in the GraphQL API",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "graphql_query",
            "description": "Execute a GraphQL query against the configured endpoint. Returns both the query used and the result data.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The GraphQL query to execute"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Optional variables for the GraphQL query",
                        "default": {}
                    }
                },
                "required": ["query"]
            }
        },
        {
            "name": "graphql_mutation",
            "description": "Execute a GraphQL mutation to modify data. Returns both the mutation used and the result.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mutation": {
                        "type": "string",
                        "description": "The GraphQL mutation to execute"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Optional variables for the mutation",
                        "default": {}
                    }
                },
                "required": ["mutation"]
            }
        },
        {
            "name": "graphql_get_schema",
            "description": "Get the human-readable GraphQL schema in SDL (Schema Definition Language) format",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    ]


async def handle_introspection() -> dict:
    """Perform GraphQL introspection"""
    logger.debug("Starting GraphQL introspection")
    client = get_graphql_client()
    introspection_query = get_introspection_query()
    
    logger.debug("Executing introspection query")
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    type_count = len(result.get("__schema", {}).get("types", []))
    logger.debug(f"Introspection completed. Found {type_count} types")
    logger.info("GraphQL introspection executed successfully")
    
    return {
        "query_used": "GraphQL Introspection Query",
        "result": result
    }


async def handle_get_schema() -> dict:
    """Get GraphQL schema in SDL format"""
    logger.debug("Starting schema retrieval")
    client = get_graphql_client()
    introspection_query = get_introspection_query()
    
    logger.debug("Executing introspection query for schema")
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    logger.debug("Building client schema from introspection result")
    schema = build_client_schema(result)
    schema_sdl = print_schema(schema)
    
    logger.debug(f"Schema SDL generated: {len(schema_sdl)} characters")
    logger.info("GraphQL schema retrieved successfully")
    
    return {
        "query_used": "GraphQL Introspection Query (converted to SDL)",
        "result": {"schema": schema_sdl}
    }


async def handle_query(arguments: dict) -> dict:
    """Execute a GraphQL query"""
    query_str = arguments.get("query", "")
    variables = arguments.get("variables", {})
    
    logger.debug(f"Query request received")
    logger.debug(f"Query: {query_str[:200]}{'...' if len(query_str) > 200 else ''}")
    if variables:
        logger.debug(f"Variables: {json.dumps(variables)[:200]}")
    
    if not query_str:
        logger.warning("Query request missing required 'query' parameter")
        raise ValueError("query parameter is required")
    
    client = get_graphql_client()
    query = gql(query_str)
    
    logger.debug("Executing GraphQL query")
    async with client as session:
        result = await session.execute(query, variable_values=variables)
    
    result_preview = json.dumps(result)[:200] if result else "null"
    logger.debug(f"Query result preview: {result_preview}{'...' if len(json.dumps(result)) > 200 else ''}")
    logger.info(f"GraphQL query executed successfully")
    
    return {
        "query_used": query_str,
        "variables": variables if variables else None,
        "result": result
    }


async def handle_mutation(arguments: dict) -> dict:
    """Execute a GraphQL mutation"""
    mutation_str = arguments.get("mutation", "")
    variables = arguments.get("variables", {})
    
    logger.debug(f"Mutation request received")
    logger.debug(f"Mutation: {mutation_str[:200]}{'...' if len(mutation_str) > 200 else ''}")
    if variables:
        logger.debug(f"Variables: {json.dumps(variables)[:200]}")
    
    if not mutation_str:
        logger.warning("Mutation request missing required 'mutation' parameter")
        raise ValueError("mutation parameter is required")
    
    client = get_graphql_client()
    mutation = gql(mutation_str)
    
    logger.debug("Executing GraphQL mutation")
    async with client as session:
        result = await session.execute(mutation, variable_values=variables)
    
    result_preview = json.dumps(result)[:200] if result else "null"
    logger.debug(f"Mutation result preview: {result_preview}{'...' if len(json.dumps(result)) > 200 else ''}")
    logger.info(f"GraphQL mutation executed successfully")
    
    return {
        "mutation_used": mutation_str,
        "variables": variables if variables else None,
        "result": result
    }


async def call_tool(name: str, arguments: dict) -> list[dict]:
    """Execute a tool and return result"""
    logger.info(f"Tool call: {name}")
    logger.debug(f"Tool arguments: {json.dumps(arguments)[:500] if arguments else 'None'}")
    
    try:
        if name == "graphql_introspection":
            logger.debug("Dispatching to introspection handler")
            result = await handle_introspection()
        elif name == "graphql_query":
            logger.debug("Dispatching to query handler")
            result = await handle_query(arguments)
        elif name == "graphql_mutation":
            logger.debug("Dispatching to mutation handler")
            result = await handle_mutation(arguments)
        elif name == "graphql_get_schema":
            logger.debug("Dispatching to schema handler")
            result = await handle_get_schema()
        else:
            logger.warning(f"Unknown tool requested: {name}")
            return [{"type": "text", "text": f"Unknown tool: {name}"}]
        
        result_size = len(json.dumps(result))
        logger.debug(f"Tool {name} completed. Result size: {result_size} bytes")
        return [{"type": "text", "text": json.dumps(result, indent=2)}]
    except Exception as e:
        logger.error(f"Error executing tool {name}: {str(e)}", exc_info=True)
        return [{"type": "text", "text": f"Error: {str(e)}"}]


def create_jsonrpc_response(id: Any, result: Any) -> dict:
    """Create a JSON-RPC 2.0 response"""
    return {
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }


def create_jsonrpc_error(id: Any, code: int, message: str) -> dict:
    """Create a JSON-RPC 2.0 error response"""
    return {
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    }


async def handle_mcp_message(message: dict) -> Optional[dict]:
    """Handle an MCP JSON-RPC message"""
    method = message.get("method")
    params = message.get("params", {})
    msg_id = message.get("id")
    
    logger.info(f"MCP request: method={method}, id={msg_id}")
    logger.debug(f"MCP message params: {json.dumps(params)[:500] if params else 'None'}")
    
    try:
        if method == "initialize":
            logger.debug("Processing initialize request")
            client_info = params.get("clientInfo", {})
            logger.info(f"Client connecting: {client_info.get('name', 'unknown')} v{client_info.get('version', 'unknown')}")
            
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
            logger.debug(f"Sending initialize response: {json.dumps(result)}")
            return create_jsonrpc_response(msg_id, result)
        
        elif method == "notifications/initialized":
            # This is a notification, no response needed
            logger.info("Client initialization complete - session ready")
            return None
        
        elif method == "tools/list":
            logger.debug("Processing tools/list request")
            tools = get_tools()
            logger.debug(f"Returning {len(tools)} tools")
            result = {"tools": tools}
            return create_jsonrpc_response(msg_id, result)
        
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            logger.info(f"Tool call requested: {tool_name}")
            logger.debug(f"Tool call arguments: {json.dumps(arguments)[:300]}")
            
            content = await call_tool(tool_name, arguments)
            result = {"content": content}
            
            logger.debug(f"Tool call completed: {tool_name}")
            return create_jsonrpc_response(msg_id, result)
        
        elif method == "ping":
            logger.debug("Received ping, sending pong")
            return create_jsonrpc_response(msg_id, {})
        
        else:
            logger.warning(f"Unknown MCP method: {method}")
            if msg_id is not None:
                return create_jsonrpc_error(msg_id, -32601, f"Method not found: {method}")
            return None
            
    except Exception as e:
        logger.error(f"Error handling MCP method {method}: {str(e)}", exc_info=True)
        if msg_id is not None:
            return create_jsonrpc_error(msg_id, -32603, str(e))
        return None


# ============================================================================
# Authentication Middleware Helper
# ============================================================================

def check_request_auth(request: Request) -> tuple[bool, Optional[dict], Optional[str]]:
    """
    Check if a request is authenticated.
    Returns: (is_authenticated, user_data, error_message)
    """
    if not GITHUB_AUTH_ENABLED:
        return True, None, None
    
    # Get token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header:
        logger.debug("No Authorization header provided")
        return False, None, "Authentication required. Please authenticate via /auth/login"
    
    # Validate token
    user_data = validate_auth_token(auth_header)
    
    if not user_data:
        logger.debug("Invalid or expired token")
        return False, None, "Invalid or expired token. Please re-authenticate via /auth/login"
    
    # Check authorization (user/org allowlists)
    if not is_user_authorized(user_data):
        logger.warning(f"User {user_data.get('user')} not authorized")
        return False, user_data, "User not authorized to access this server"
    
    logger.debug(f"Request authenticated for user: {user_data.get('user')}")
    return True, user_data, None


# HTTP Endpoints

async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "auth_enabled": GITHUB_AUTH_ENABLED
    })


async def mcp_post_endpoint(request: Request) -> Response:
    """
    Main MCP endpoint - handles POST requests with JSON-RPC messages
    This is the Streamable HTTP transport endpoint
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"POST request from {client_ip}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    
    # Check authentication if enabled
    is_authed, user_data, error_msg = check_request_auth(request)
    if not is_authed:
        logger.warning(f"Unauthenticated MCP POST request from {client_ip}: {error_msg}")
        return JSONResponse(
            {"error": error_msg, "auth_url": "/auth/login"},
            status_code=401
        )
    
    try:
        body = await request.json()
        logger.info(f"MCP POST received from {client_ip}: {json.dumps(body)[:200]}")
        
        # Handle single message or batch
        if isinstance(body, list):
            responses = []
            for msg in body:
                response = await handle_mcp_message(msg)
                if response:
                    responses.append(response)
            if responses:
                return JSONResponse(responses if len(responses) > 1 else responses[0])
            return Response(status_code=202)
        else:
            response = await handle_mcp_message(body)
            if response:
                return JSONResponse(response)
            return Response(status_code=202)
            
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {str(e)}")
        return JSONResponse(
            create_jsonrpc_error(None, -32700, "Parse error"),
            status_code=400
        )
    except Exception as e:
        logger.error(f"Error handling POST: {str(e)}", exc_info=True)
        return JSONResponse(
            create_jsonrpc_error(None, -32603, str(e)),
            status_code=500
        )


async def mcp_sse_endpoint(request: Request) -> EventSourceResponse:
    """
    SSE endpoint for MCP - provides server-to-client streaming
    Used as fallback or for notifications
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Check authentication if enabled
    is_authed, user_data, error_msg = check_request_auth(request)
    if not is_authed:
        logger.warning(f"Unauthenticated SSE request from {client_ip}: {error_msg}")
        # Return a simple error response for SSE
        async def error_generator():
            yield {
                "event": "error",
                "data": json.dumps({"error": error_msg, "auth_url": "/auth/login"})
            }
        return EventSourceResponse(error_generator())
    
    session_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    sse_connections[session_id] = queue
    
    user_info = f" (user: {user_data.get('user')})" if user_data else ""
    logger.info(f"SSE connection established: session={session_id}, client={client_ip}{user_info}")
    logger.debug(f"Active SSE connections: {len(sse_connections)}")
    
    async def event_generator():
        try:
            # Send endpoint info for client to POST to
            yield {
                "event": "endpoint",
                "data": f"/messages?session_id={session_id}"
            }
            
            # Keep connection alive and send any queued messages
            while True:
                try:
                    # Wait for messages with timeout for keepalive
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {
                        "event": "message",
                        "data": json.dumps(message)
                    }
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield {
                        "event": "ping",
                        "data": json.dumps({"type": "ping"})
                    }
        except asyncio.CancelledError:
            logger.info(f"SSE connection closed: {session_id}")
        finally:
            sse_connections.pop(session_id, None)
    
    return EventSourceResponse(event_generator())


async def mcp_messages_endpoint(request: Request) -> Response:
    """
    Handle messages posted to a specific SSE session
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Check authentication if enabled
    is_authed, user_data, error_msg = check_request_auth(request)
    if not is_authed:
        logger.warning(f"Unauthenticated messages request from {client_ip}: {error_msg}")
        return JSONResponse(
            {"error": error_msg, "auth_url": "/auth/login"},
            status_code=401
        )
    
    session_id = request.query_params.get("session_id")
    
    if not session_id or session_id not in sse_connections:
        return JSONResponse(
            {"error": "Invalid or expired session"},
            status_code=400
        )
    
    try:
        body = await request.json()
        logger.info(f"Received message for session {session_id}: {json.dumps(body)[:200]}")
        
        response = await handle_mcp_message(body)
        
        if response:
            # Send response through SSE
            queue = sse_connections.get(session_id)
            if queue:
                await queue.put(response)
            return Response(status_code=202)
        
        return Response(status_code=202)
        
    except Exception as e:
        logger.error(f"Error handling message: {str(e)}", exc_info=True)
        return JSONResponse(
            {"error": str(e)},
            status_code=500
        )


async def list_tools_endpoint(request: Request) -> JSONResponse:
    """List available tools - convenience endpoint"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check authentication if enabled
    is_authed, user_data, error_msg = check_request_auth(request)
    if not is_authed:
        logger.warning(f"Unauthenticated tools list request from {client_ip}: {error_msg}")
        return JSONResponse(
            {"error": error_msg, "auth_url": "/auth/login"},
            status_code=401
        )
    
    return JSONResponse({"tools": get_tools()})


async def execute_tool_endpoint(request: Request) -> JSONResponse:
    """Execute a tool - convenience endpoint"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check authentication if enabled
    is_authed, user_data, error_msg = check_request_auth(request)
    if not is_authed:
        logger.warning(f"Unauthenticated execute request from {client_ip}: {error_msg}")
        return JSONResponse(
            {"error": error_msg, "auth_url": "/auth/login"},
            status_code=401
        )
    
    try:
        body = await request.json()
        tool_name = body.get("tool")
        arguments = body.get("arguments", {})
        
        if not tool_name:
            return JSONResponse({"error": "tool parameter is required"}, status_code=400)
        
        result = await call_tool(tool_name, arguments)
        
        return JSONResponse({
            "tool": tool_name,
            "result": result
        })
    except Exception as e:
        logger.error(f"Error executing tool: {str(e)}", exc_info=True)
        return JSONResponse({"error": str(e)}, status_code=500)


# CORS middleware (always enabled)
cors_middleware = Middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Build middleware list
middleware = [cors_middleware]

# Add GitHub auth middleware if enabled
if GITHUB_AUTH_ENABLED:
    middleware.append(Middleware(GitHubAuthMiddleware))
    logger.info("GitHub OAuth authentication enabled")

# Create Starlette app with all routes
app = Starlette(
    debug=True,
    routes=[
        # MCP protocol endpoints
        Route("/", mcp_post_endpoint, methods=["POST"]),
        Route("/", mcp_sse_endpoint, methods=["GET"]),
        Route("/sse", mcp_sse_endpoint, methods=["GET"]),
        Route("/messages", mcp_messages_endpoint, methods=["POST"]),
        
        # Authentication endpoints
        Route("/auth/login", auth_login, methods=["GET"], name="auth_login"),
        Route("/auth/callback", auth_callback, methods=["GET"], name="auth_callback"),
        Route("/auth/status", auth_status, methods=["GET"]),
        Route("/auth/logout", auth_logout, methods=["POST"]),
        
        # Convenience endpoints
        Route("/health", health_check, methods=["GET"]),
        Route("/tools", list_tools_endpoint, methods=["GET"]),
        Route("/execute", execute_tool_endpoint, methods=["POST"]),
    ],
    middleware=middleware
)


def run_server():
    """Run the HTTP/SSE server"""
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8000"))
    
    logger.info("=" * 60)
    logger.info(f"GraphQL MCP Server v{SERVER_VERSION}")
    logger.info("=" * 60)
    logger.info(f"Host: {host}")
    logger.info(f"Port: {port}")
    logger.info(f"GraphQL Endpoint: {os.getenv('GRAPHQL_ENDPOINT', 'Not configured')}")
    logger.info(f"MCP Protocol Version: {PROTOCOL_VERSION}")
    logger.info(f"Log Level: {LOG_LEVEL}")
    logger.info(f"GitHub Auth: {'Enabled' if GITHUB_AUTH_ENABLED else 'Disabled'}")
    if GITHUB_AUTH_ENABLED:
        logger.info(f"  Allowed Users: {GITHUB_ALLOWED_USERS or 'Any authenticated user'}")
        logger.info(f"  Allowed Orgs: {GITHUB_ALLOWED_ORGS or 'Any'}")
    logger.info("=" * 60)
    logger.info("Available endpoints:")
    logger.info("  POST /          - MCP JSON-RPC endpoint")
    logger.info("  GET  /          - SSE endpoint")
    logger.info("  GET  /sse       - SSE endpoint (alias)")
    logger.info("  GET  /health    - Health check")
    logger.info("  GET  /tools     - List tools")
    logger.info("  POST /execute   - Execute tool directly")
    if GITHUB_AUTH_ENABLED:
        logger.info("  GET  /auth/login    - Start OAuth login")
        logger.info("  GET  /auth/callback - OAuth callback")
        logger.info("  GET  /auth/status   - Check auth status")
        logger.info("  POST /auth/logout   - Logout")
    logger.info("=" * 60)
    
    # Determine uvicorn log level based on our LOG_LEVEL
    uvicorn_log_level = "debug" if LOG_LEVEL == "DEBUG" else "info"
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=uvicorn_log_level
    )


if __name__ == "__main__":
    run_server()
