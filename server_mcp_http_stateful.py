"""
GraphQL MCP Server with Streamable HTTP Transport (Stateful)

This is a proper stateful MCP server using the official MCP SDK's
StreamableHTTPSessionManager for session management and resumability.

Features:
- Stateful session management with Mcp-Session-Id tracking
- SSE stream resumability with Last-Event-ID support
- Proper lifecycle management
- GitHub OAuth authentication (optional)
- GraphQL introspection, query, mutation tools
- Epoch time conversion utility
"""

import os
import json
import logging
import contextlib
import time
import secrets
from typing import Any, Optional
from collections.abc import AsyncIterator

import anyio
import aiohttp
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.middleware.cors import CORSMiddleware
from starlette.types import Receive, Scope, Send
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import get_introspection_query, build_client_schema, print_schema
from dotenv import load_dotenv
import uvicorn

from event_store import InMemoryEventStore

# Import version info
try:
    from version import __version__, MCP_PROTOCOL_VERSION, SERVER_NAME
except ImportError:
    __version__ = "1.0.0"
    MCP_PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "graphql-mcp-server"

# Load environment variables
load_dotenv()

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Reduce noise from third-party loggers
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
AUTH_TOKEN_EXPIRY = int(os.getenv("AUTH_TOKEN_EXPIRY", "86400"))

# Token storage (in production, use Redis or database)
oauth_states: dict[str, dict] = {}
auth_tokens: dict[str, dict] = {}

# SSL Configuration
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() != "false"
if not SSL_VERIFY:
    logger.warning("⚠️  SSL certificate verification is DISABLED - use only in development!")

# Global GraphQL client
graphql_client: Optional[Client] = None


# ============================================================================
# GraphQL Client
# ============================================================================

def get_graphql_client() -> Client:
    """Get or create GraphQL client"""
    global graphql_client
    
    if graphql_client is None:
        endpoint = os.getenv("GRAPHQL_ENDPOINT")
        if not endpoint:
            raise ValueError("GRAPHQL_ENDPOINT environment variable is required")
        
        headers = {}
        auth_token = os.getenv("GRAPHQL_AUTH_TOKEN")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        custom_headers = os.getenv("GRAPHQL_HEADERS")
        if custom_headers:
            try:
                headers.update(json.loads(custom_headers))
            except json.JSONDecodeError:
                logger.warning("Invalid GRAPHQL_HEADERS format, skipping")
        
        ssl_param = False if not SSL_VERIFY else None
        logger.info(f"SSL Configuration: SSL_VERIFY={SSL_VERIFY}, ssl_param={ssl_param}")
        
        transport = AIOHTTPTransport(
            url=endpoint,
            headers=headers,
            ssl=ssl_param
        )
        graphql_client = Client(transport=transport, fetch_schema_from_transport=False)
        logger.info(f"GraphQL client initialized for: {endpoint}")
    
    return graphql_client


# ============================================================================
# Tool Handlers
# ============================================================================

async def handle_introspection() -> dict:
    """Perform GraphQL introspection"""
    client = get_graphql_client()
    introspection_query = get_introspection_query()
    
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    logger.info("GraphQL introspection executed successfully")
    return {
        "query_used": "GraphQL Introspection Query",
        "result": result
    }


async def handle_get_schema() -> dict:
    """Get GraphQL schema in SDL format"""
    client = get_graphql_client()
    introspection_query = get_introspection_query()
    
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    schema = build_client_schema(result)
    schema_sdl = print_schema(schema)
    
    logger.info("GraphQL schema retrieved successfully")
    return {
        "query_used": "GraphQL Introspection Query (converted to SDL)",
        "result": {"schema": schema_sdl}
    }


async def handle_query(query_str: str, variables: Optional[dict] = None) -> dict:
    """Execute a GraphQL query"""
    if not query_str:
        raise ValueError("query parameter is required")
    
    client = get_graphql_client()
    query = gql(query_str)
    
    async with client as session:
        result = await session.execute(query, variable_values=variables or {})
    
    logger.info("GraphQL query executed successfully")
    return {
        "query_used": query_str,
        "variables": variables if variables else None,
        "result": result
    }


async def handle_mutation(mutation_str: str, variables: Optional[dict] = None) -> dict:
    """Execute a GraphQL mutation"""
    if not mutation_str:
        raise ValueError("mutation parameter is required")
    
    client = get_graphql_client()
    mutation = gql(mutation_str)
    
    async with client as session:
        result = await session.execute(mutation, variable_values=variables or {})
    
    logger.info("GraphQL mutation executed successfully")
    return {
        "mutation_used": mutation_str,
        "variables": variables if variables else None,
        "result": result
    }


async def handle_epoch_to_readable(
    epoch: float, 
    format_str: str = "%Y-%m-%d %H:%M:%S UTC", 
    timezone: str = "UTC"
) -> dict:
    """Convert epoch timestamp to readable format"""
    utc_time = time.gmtime(epoch)
    
    if timezone == "UTC":
        readable = time.strftime(format_str, utc_time)
    else:
        original_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = timezone
            time.tzset()
            local_time = time.localtime(epoch)
            adjusted_format = format_str.replace(" UTC", f" {timezone}").replace("UTC", timezone)
            readable = time.strftime(adjusted_format, local_time)
        finally:
            if original_tz:
                os.environ["TZ"] = original_tz
            else:
                os.environ.pop("TZ", None)
            time.tzset()
    
    return {
        "epoch": epoch,
        "readable": readable,
        "iso8601": time.strftime("%Y-%m-%dT%H:%M:%SZ", utc_time),
        "timezone": timezone,
        "components": {
            "year": utc_time.tm_year,
            "month": utc_time.tm_mon,
            "day": utc_time.tm_mday,
            "hour": utc_time.tm_hour,
            "minute": utc_time.tm_min,
            "second": utc_time.tm_sec,
            "weekday": time.strftime("%A", utc_time),
            "day_of_year": utc_time.tm_yday
        }
    }


# ============================================================================
# GitHub OAuth Functions
# ============================================================================

def generate_oauth_state() -> str:
    return secrets.token_urlsafe(32)


def generate_auth_token() -> str:
    return secrets.token_urlsafe(64)


def cleanup_expired_tokens():
    current_time = time.time()
    
    expired_states = [s for s, data in oauth_states.items() 
                      if current_time - data["created_at"] > 300]
    for state in expired_states:
        oauth_states.pop(state, None)
    
    expired_tokens = [t for t, data in auth_tokens.items() 
                      if current_time > data["expires_at"]]
    for token in expired_tokens:
        auth_tokens.pop(token, None)


def validate_auth_token(token: str) -> Optional[dict]:
    cleanup_expired_tokens()
    
    if not token:
        return None
    
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
    username = user_data.get("user", "")
    user_orgs = user_data.get("orgs", [])
    
    if not GITHUB_ALLOWED_USERS and not GITHUB_ALLOWED_ORGS:
        return True
    
    if username in GITHUB_ALLOWED_USERS:
        return True
    
    for org in user_orgs:
        if org in GITHUB_ALLOWED_ORGS:
            return True
    
    return False


async def fetch_github_user(access_token: str) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            async with session.get("https://api.github.com/user", headers=headers) as resp:
                if resp.status != 200:
                    return None
                user_info = await resp.json()
            
            async with session.get("https://api.github.com/user/orgs", headers=headers) as resp:
                orgs = [org["login"] for org in await resp.json()] if resp.status == 200 else []
            
            return {
                "login": user_info.get("login"),
                "id": user_info.get("id"),
                "name": user_info.get("name"),
                "email": user_info.get("email"),
                "orgs": orgs
            }
    except Exception as e:
        logger.error(f"Error fetching GitHub user: {e}")
        return None


async def exchange_code_for_token(code: str) -> Optional[str]:
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
                    return None
                result = await resp.json()
                if "error" in result:
                    return None
                return result.get("access_token")
    except Exception as e:
        logger.error(f"Error exchanging OAuth code: {e}")
        return None


# ============================================================================
# OAuth HTTP Endpoints
# ============================================================================

async def auth_login(request: Request) -> Response:
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({"error": "GitHub authentication is not enabled"}, status_code=400)
    
    if not GITHUB_CLIENT_ID:
        return JSONResponse({"error": "GitHub OAuth not configured"}, status_code=500)
    
    state = generate_oauth_state()
    redirect_uri = request.query_params.get("redirect_uri", "")
    
    oauth_states[state] = {
        "created_at": time.time(),
        "redirect_uri": redirect_uri
    }
    
    callback_url = GITHUB_OAUTH_CALLBACK_URL or str(request.url_for("auth_callback"))
    
    from urllib.parse import urlencode
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": callback_url,
        "scope": "read:user read:org",
        "state": state
    }
    
    github_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=github_url)


async def auth_callback(request: Request) -> Response:
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({"error": "GitHub authentication is not enabled"}, status_code=400)
    
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    
    if not code or not state:
        return JSONResponse({"error": "Missing code or state"}, status_code=400)
    
    state_data = oauth_states.pop(state, None)
    if not state_data:
        return JSONResponse({"error": "Invalid or expired state"}, status_code=400)
    
    access_token = await exchange_code_for_token(code)
    if not access_token:
        return JSONResponse({"error": "Failed to exchange code"}, status_code=400)
    
    user_info = await fetch_github_user(access_token)
    if not user_info:
        return JSONResponse({"error": "Failed to fetch user info"}, status_code=400)
    
    temp_user_data = {"user": user_info["login"], "orgs": user_info["orgs"]}
    if not is_user_authorized(temp_user_data):
        return JSONResponse({
            "error": "Forbidden",
            "message": f"User {user_info['login']} is not authorized"
        }, status_code=403)
    
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
    
    redirect_uri = state_data.get("redirect_uri")
    if redirect_uri:
        return RedirectResponse(url=f"{redirect_uri}#token={auth_token}")
    
    return JSONResponse({
        "success": True,
        "token": auth_token,
        "user": user_info["login"],
        "expires_in": AUTH_TOKEN_EXPIRY
    })


async def auth_status(request: Request) -> JSONResponse:
    if not GITHUB_AUTH_ENABLED:
        return JSONResponse({"auth_enabled": False})
    
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
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token in auth_tokens:
            auth_tokens.pop(token, None)
            return JSONResponse({"success": True, "message": "Logged out successfully"})
    
    return JSONResponse({"success": True, "message": "No active session"})


# ============================================================================
# Convenience HTTP Endpoints
# ============================================================================

async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "healthy",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "stateful": True,
        "auth_enabled": GITHUB_AUTH_ENABLED
    })


async def list_tools_endpoint(request: Request) -> JSONResponse:
    tools = [
        {"name": "graphql_introspection", "description": "Perform GraphQL introspection"},
        {"name": "graphql_query", "description": "Execute a GraphQL query"},
        {"name": "graphql_mutation", "description": "Execute a GraphQL mutation"},
        {"name": "graphql_get_schema", "description": "Get GraphQL schema in SDL format"},
        {"name": "epoch_to_readable", "description": "Convert epoch timestamp to readable format"}
    ]
    return JSONResponse({"tools": tools})


async def execute_tool_endpoint(request: Request) -> JSONResponse:
    """Direct tool execution endpoint for testing"""
    try:
        body = await request.json()
        tool_name = body.get("tool")
        arguments = body.get("arguments", {})
        
        if tool_name == "graphql_introspection":
            result = await handle_introspection()
        elif tool_name == "graphql_query":
            result = await handle_query(arguments.get("query", ""), arguments.get("variables"))
        elif tool_name == "graphql_mutation":
            result = await handle_mutation(arguments.get("mutation", ""), arguments.get("variables"))
        elif tool_name == "graphql_get_schema":
            result = await handle_get_schema()
        elif tool_name == "epoch_to_readable":
            result = await handle_epoch_to_readable(
                arguments.get("epoch", 0),
                arguments.get("format", "%Y-%m-%d %H:%M:%S UTC"),
                arguments.get("timezone", "UTC")
            )
        else:
            return JSONResponse({"error": f"Unknown tool: {tool_name}"}, status_code=400)
        
        return JSONResponse({"tool": tool_name, "result": result})
    except Exception as e:
        logger.error(f"Error executing tool: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================================
# MCP Server Setup with StreamableHTTPSessionManager
# ============================================================================

def create_mcp_server() -> Server:
    """Create and configure the MCP server with tools"""
    
    mcp_app = Server(SERVER_NAME)
    
    @mcp_app.list_tools()
    async def list_tools() -> list[types.Tool]:
        """List available tools"""
        return [
            types.Tool(
                name="graphql_introspection",
                description="Perform GraphQL introspection to discover the schema, types, queries, mutations, and fields available in the GraphQL API",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="graphql_query",
                description="Execute a GraphQL query against the configured endpoint. Returns both the query used and the result data.",
                inputSchema={
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
            ),
            types.Tool(
                name="graphql_mutation",
                description="Execute a GraphQL mutation to modify data. Returns both the mutation used and the result.",
                inputSchema={
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
            ),
            types.Tool(
                name="graphql_get_schema",
                description="Get the human-readable GraphQL schema in SDL (Schema Definition Language) format",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="epoch_to_readable",
                description="Convert Unix epoch timestamp to human-readable date/time format",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "epoch": {
                            "type": "number",
                            "description": "Unix epoch timestamp (seconds since January 1, 1970)"
                        },
                        "format": {
                            "type": "string",
                            "description": "Optional strftime format string (default: '%Y-%m-%d %H:%M:%S UTC')",
                            "default": "%Y-%m-%d %H:%M:%S UTC"
                        },
                        "timezone": {
                            "type": "string",
                            "description": "Optional timezone name (e.g., 'US/Eastern', 'Europe/London'). Defaults to UTC.",
                            "default": "UTC"
                        }
                    },
                    "required": ["epoch"]
                }
            )
        ]
    
    @mcp_app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        """Handle tool calls"""
        logger.info(f"Tool call: {name}")
        logger.debug(f"Arguments: {json.dumps(arguments)[:500] if arguments else 'None'}")
        
        try:
            if name == "graphql_introspection":
                result = await handle_introspection()
            elif name == "graphql_query":
                result = await handle_query(
                    arguments.get("query", ""),
                    arguments.get("variables")
                )
            elif name == "graphql_mutation":
                result = await handle_mutation(
                    arguments.get("mutation", ""),
                    arguments.get("variables")
                )
            elif name == "graphql_get_schema":
                result = await handle_get_schema()
            elif name == "epoch_to_readable":
                epoch = arguments.get("epoch")
                if epoch is None:
                    raise ValueError("epoch parameter is required")
                result = await handle_epoch_to_readable(
                    epoch,
                    arguments.get("format", "%Y-%m-%d %H:%M:%S UTC"),
                    arguments.get("timezone", "UTC")
                )
            else:
                return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
        except Exception as e:
            logger.error(f"Error executing tool {name}: {e}", exc_info=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
    
    return mcp_app


# ============================================================================
# Authentication Middleware for MCP Endpoint
# ============================================================================

class AuthenticatedMCPHandler:
    """Wrapper to add authentication to MCP endpoint"""
    
    def __init__(self, session_manager: StreamableHTTPSessionManager):
        self.session_manager = session_manager
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if GITHUB_AUTH_ENABLED:
            # Extract Authorization header
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()
            
            token_data = validate_auth_token(auth_header)
            
            if not token_data:
                response = JSONResponse(
                    {"error": "Unauthorized", "login_url": "/auth/login"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
            
            if not is_user_authorized(token_data):
                response = JSONResponse(
                    {"error": "Forbidden", "message": "User not authorized"},
                    status_code=403
                )
                await response(scope, receive, send)
                return
        
        # Pass to session manager
        await self.session_manager.handle_request(scope, receive, send)


# ============================================================================
# Application Factory
# ============================================================================

def create_app() -> Starlette:
    """Create the Starlette application with MCP session manager"""
    
    # Create MCP server
    mcp_server = create_mcp_server()
    
    # Create event store for resumability
    event_store = InMemoryEventStore(
        max_events_per_stream=1000,
        event_ttl_seconds=3600
    )
    
    # Create session manager
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        event_store=event_store,
        json_response=False  # Use SSE streams
    )
    
    # Create authenticated MCP handler
    mcp_handler = AuthenticatedMCPHandler(session_manager)
    
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        """Manage application lifecycle"""
        async with session_manager.run():
            logger.info("MCP Session Manager started")
            try:
                yield
            finally:
                logger.info("MCP Session Manager shutting down")
    
    # Create routes - specific routes MUST come before catch-all mounts
    routes = [
        # Health and convenience endpoints (must be first)
        Route("/health", health_check, methods=["GET"]),
        Route("/tools", list_tools_endpoint, methods=["GET"]),
        Route("/execute", execute_tool_endpoint, methods=["POST"]),
        
        # OAuth endpoints
        Route("/auth/login", auth_login, methods=["GET"], name="auth_login"),
        Route("/auth/callback", auth_callback, methods=["GET"], name="auth_callback"),
        Route("/auth/status", auth_status, methods=["GET"]),
        Route("/auth/logout", auth_logout, methods=["POST"]),
        
        # MCP endpoint (mounted under /mcp for explicit access)
        Mount("/mcp", app=mcp_handler),
    ]
    
    app = Starlette(
        debug=LOG_LEVEL == "DEBUG",
        routes=routes,
        lifespan=lifespan
    )
    
    # Wrap with CORS middleware
    app = CORSMiddleware(
        app,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id"],
    )
    
    return app


# ============================================================================
# Main Entry Point
# ============================================================================

def run_server():
    """Run the MCP server"""
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8000"))
    
    logger.info("=" * 60)
    logger.info(f"GraphQL MCP Server v{SERVER_VERSION} (Stateful)")
    logger.info("=" * 60)
    logger.info(f"Host: {host}")
    logger.info(f"Port: {port}")
    logger.info(f"GraphQL Endpoint: {os.getenv('GRAPHQL_ENDPOINT', 'Not configured')}")
    logger.info(f"MCP Protocol Version: {PROTOCOL_VERSION}")
    logger.info(f"Log Level: {LOG_LEVEL}")
    logger.info(f"SSL Verify: {SSL_VERIFY}")
    logger.info(f"GitHub Auth: {'Enabled' if GITHUB_AUTH_ENABLED else 'Disabled'}")
    logger.info("=" * 60)
    logger.info("Session Management: StreamableHTTPSessionManager")
    logger.info("Resumability: Enabled (InMemoryEventStore)")
    logger.info("=" * 60)
    logger.info("Endpoints:")
    logger.info("  /mcp    - MCP Streamable HTTP endpoint")
    logger.info("  /health - Health check")
    logger.info("  /tools  - List available tools")
    logger.info("  /execute - Direct tool execution")
    if GITHUB_AUTH_ENABLED:
        logger.info("  /auth/* - OAuth endpoints")
    logger.info("=" * 60)
    
    app = create_app()
    
    uvicorn_log_level = "debug" if LOG_LEVEL == "DEBUG" else "info"
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=uvicorn_log_level
    )


if __name__ == "__main__":
    run_server()
