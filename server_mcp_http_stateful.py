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

from event_store import InMemoryEventStore, RedisEventStore

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

# OAuth 2.1 Configuration
OAUTH_ENABLED = os.getenv("OAUTH_ENABLED", os.getenv("GITHUB_AUTH_ENABLED", "false")).lower() == "true"
OAUTH_PROVIDER = os.getenv("OAUTH_PROVIDER", "github")

# Import OAuth 2.1 module if enabled
if OAUTH_ENABLED:
    try:
        from oauth21 import (
            get_oauth_client, get_oauth_config, token_store,
            validate_bearer_token, OAuth21Client, TokenSet
        )
        oauth_client = get_oauth_client(OAUTH_PROVIDER)
        if oauth_client:
            logger.info(f"OAuth 2.1 enabled with provider: {OAUTH_PROVIDER}")
        else:
            logger.warning(f"OAuth 2.1 enabled but provider '{OAUTH_PROVIDER}' not configured")
            OAUTH_ENABLED = False
    except ImportError as e:
        logger.warning(f"OAuth 2.1 module not available: {e}")
        OAUTH_ENABLED = False
        oauth_client = None

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
# OAuth 2.1 Authorization Server Endpoints (RFC 8414)
# ============================================================================

def get_external_base_url(request: Request) -> str:
    """
    Get the external base URL, respecting X-Forwarded-* headers from reverse proxies.
    """
    # Check for X-Forwarded-Proto header (set by Traefik/nginx)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    
    # Check for X-Forwarded-Host header
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    
    # Build the base URL
    return f"{proto}://{host}"


async def oauth_metadata(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    Returns server metadata for MCP client discovery.
    """
    # Get the base URL respecting proxy headers
    base_url = get_external_base_url(request)
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "token_endpoint_auth_methods_supported": ["none"],  # Public client
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"],
        "service_documentation": f"{base_url}/docs"
    }
    
    if OAUTH_ENABLED:
        metadata["revocation_endpoint"] = f"{base_url}/auth/revoke"
        # Provide the public client ID for VS Code and other MCP clients
        # This is safe to expose as it's a public OAuth client identifier
        oauth_config = get_oauth_config(OAUTH_PROVIDER)
        if oauth_config and oauth_config.client_id:
            metadata["client_id"] = oauth_config.client_id
            metadata["client_id_hint"] = f"Use this Client ID when connecting: {oauth_config.client_id}"
    
    return JSONResponse(metadata)


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Protected Resource Metadata (RFC 9728)
    Tells MCP clients how to authenticate with this server.
    """
    base_url = get_external_base_url(request)
    
    metadata = {
        "resource": base_url,
        "authorization_servers": [base_url],
        "scopes_supported": ["openid", "profile", "email"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/docs"
    }
    
    return JSONResponse(metadata)


async def oauth_authorize(request: Request) -> Response:
    """
    OAuth 2.1 Authorization endpoint.
    Proxies to the configured OAuth provider (e.g., GitHub).
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    # Extract OAuth parameters from the request
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    response_type = request.query_params.get("response_type")
    state = request.query_params.get("state")
    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method")
    scope = request.query_params.get("scope", "")
    
    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    
    # Get OAuth client for provider
    client = get_oauth_client(OAUTH_PROVIDER)
    if not client:
        return JSONResponse({"error": f"OAuth provider '{OAUTH_PROVIDER}' not configured"}, status_code=500)
    
    # Create authorization URL with PKCE to the upstream provider
    # We'll store the client's PKCE challenge and state so we can relay them back
    callback_url = client.config.redirect_uri or str(request.url_for("auth_callback"))
    
    # Create our own auth request to the upstream provider
    auth_url, auth_request = client.create_authorization_url(
        redirect_uri=callback_url,
        client_redirect_uri=redirect_uri  # Store original redirect_uri
    )
    
    # Store mapping: our state -> client's state and code_challenge
    auth_request.metadata = {
        "client_state": state,
        "client_redirect_uri": redirect_uri,
        "client_code_challenge": code_challenge,
        "client_code_challenge_method": code_challenge_method,
        "client_id": client_id
    }
    token_store.store_auth_request(auth_request)
    
    logger.debug(f"Proxying authorization to {OAUTH_PROVIDER}, state={auth_request.state}")
    return RedirectResponse(url=auth_url)


async def oauth_token(request: Request) -> JSONResponse:
    """
    OAuth 2.1 Token endpoint.
    Exchanges authorization code for tokens.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    try:
        # Accept both form-encoded and JSON
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            body = await request.json()
        else:
            form = await request.form()
            body = dict(form)
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    
    grant_type = body.get("grant_type")
    
    if grant_type == "authorization_code":
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        code_verifier = body.get("code_verifier")
        
        if not code:
            return JSONResponse({"error": "invalid_request", "error_description": "code is required"}, status_code=400)
        
        # Look up the stored token by code
        token_set = token_store.get_token_by_code(code)
        if not token_set:
            return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)
        
        # Verify PKCE if provided
        if token_set.metadata and token_set.metadata.get("client_code_challenge"):
            if not code_verifier:
                return JSONResponse({"error": "invalid_request", "error_description": "code_verifier required"}, status_code=400)
            
            # Verify S256 challenge
            import hashlib
            import base64
            computed = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            
            if computed != token_set.metadata["client_code_challenge"]:
                return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, status_code=400)
        
        # Mark code as used (one-time use)
        token_store.consume_code(code)
        
        return JSONResponse({
            "access_token": token_set.access_token,
            "token_type": "Bearer",
            "expires_in": int(token_set.expires_at - time.time()),
            "refresh_token": token_set.refresh_token,
            "scope": token_set.scope
        })
    
    elif grant_type == "refresh_token":
        refresh_token = body.get("refresh_token")
        if not refresh_token:
            return JSONResponse({"error": "invalid_request", "error_description": "refresh_token required"}, status_code=400)
        
        # Get existing token
        old_token_set = token_store.get_token_by_refresh(refresh_token)
        if not old_token_set:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        
        # Refresh with upstream provider
        client = get_oauth_client(old_token_set.provider)
        if client:
            new_token_set = await client.refresh_tokens(refresh_token)
            if new_token_set:
                token_store.rotate_refresh_token(refresh_token, new_token_set)
                return JSONResponse({
                    "access_token": new_token_set.access_token,
                    "token_type": "Bearer",
                    "expires_in": int(new_token_set.expires_at - time.time()),
                    "refresh_token": new_token_set.refresh_token,
                    "scope": new_token_set.scope
                })
        
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


# ============================================================================
# OAuth 2.1 HTTP Endpoints
# ============================================================================

async def auth_login(request: Request) -> Response:
    """
    Initiate OAuth 2.1 authorization flow with PKCE.
    
    Query params:
        redirect_uri: Optional URI to redirect user after authentication
        provider: OAuth provider (default: from OAUTH_PROVIDER env var)
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    provider = request.query_params.get("provider", OAUTH_PROVIDER)
    client = get_oauth_client(provider)
    
    if not client:
        return JSONResponse({"error": f"OAuth provider '{provider}' not configured"}, status_code=500)
    
    # Get callback URL
    callback_url = client.config.redirect_uri or str(request.url_for("auth_callback"))
    client_redirect = request.query_params.get("redirect_uri", "")
    
    # Create authorization URL with PKCE
    auth_url, auth_request = client.create_authorization_url(
        redirect_uri=callback_url,
        client_redirect_uri=client_redirect
    )
    
    # Store the auth request (includes PKCE verifier)
    token_store.store_auth_request(auth_request)
    
    logger.debug(f"Redirecting to OAuth provider: {provider}")
    return RedirectResponse(url=auth_url)


async def auth_callback(request: Request) -> Response:
    """
    OAuth 2.1 callback endpoint - exchanges code for tokens using PKCE.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        error_description = request.query_params.get("error_description", "Unknown error")
        logger.error(f"OAuth error: {error} - {error_description}")
        return JSONResponse({"error": error, "description": error_description}, status_code=400)
    
    if not code or not state:
        return JSONResponse({"error": "Missing code or state parameter"}, status_code=400)
    
    # Retrieve the auth request (contains PKCE verifier)
    auth_request = token_store.get_auth_request(state)
    if not auth_request:
        return JSONResponse({"error": "Invalid or expired state - please try again"}, status_code=400)
    
    # Get the OAuth client for this provider
    client = get_oauth_client(auth_request.provider)
    if not client:
        return JSONResponse({"error": "OAuth provider not found"}, status_code=500)
    
    # Exchange code for tokens (with PKCE verifier)
    token_set = await client.exchange_code(code, auth_request)
    if not token_set:
        return JSONResponse({"error": "Failed to exchange authorization code"}, status_code=400)
    
    # Check authorization
    if not client.is_user_authorized(token_set):
        logger.warning(f"Unauthorized user attempted login: {token_set.username}")
        return JSONResponse({
            "error": "Forbidden",
            "message": f"User {token_set.username} is not authorized to access this server"
        }, status_code=403)
    
    # Store the token
    token_store.store_token(token_set)
    
    logger.info(f"User {token_set.username} authenticated successfully via {auth_request.provider}")
    
    # Check if this came from /authorize flow (has client metadata)
    if hasattr(auth_request, 'metadata') and auth_request.metadata:
        client_redirect_uri = auth_request.metadata.get("client_redirect_uri")
        client_state = auth_request.metadata.get("client_state")
        
        if client_redirect_uri:
            # Generate an authorization code for the client
            auth_code = secrets.token_urlsafe(32)
            
            # Store token with the code for later exchange
            token_set.metadata = auth_request.metadata
            token_store.store_token_with_code(auth_code, token_set)
            
            # Build redirect URL with code and state (OAuth 2.1 standard flow)
            redirect_url = f"{client_redirect_uri}?code={auth_code}"
            if client_state:
                redirect_url += f"&state={client_state}"
            
            logger.debug(f"Redirecting to client with auth code: {client_redirect_uri}")
            return RedirectResponse(url=redirect_url)
    
    # Legacy flow: Redirect with token or return JSON
    if auth_request.client_redirect_uri:
        # Fragment-based redirect (more secure than query param)
        return RedirectResponse(
            url=f"{auth_request.client_redirect_uri}#access_token={token_set.access_token}&token_type=Bearer&expires_in={int(token_set.expires_at - time.time())}"
        )
    
    return JSONResponse({
        "success": True,
        "access_token": token_set.access_token,
        "token_type": "Bearer",
        "expires_in": int(token_set.expires_at - time.time()),
        "refresh_token": token_set.refresh_token,
        "user": token_set.username,
        "scope": token_set.scope
    })


async def auth_refresh(request: Request) -> JSONResponse:
    """
    Refresh access token using refresh token.
    OAuth 2.1 implements refresh token rotation for security.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    try:
        body = await request.json()
        refresh_token = body.get("refresh_token")
    except Exception:
        return JSONResponse({"error": "Invalid request body"}, status_code=400)
    
    if not refresh_token:
        return JSONResponse({"error": "refresh_token is required"}, status_code=400)
    
    # Get existing token to find provider
    old_token_set = token_store.get_token_by_refresh(refresh_token)
    if not old_token_set:
        return JSONResponse({"error": "Invalid refresh token"}, status_code=401)
    
    client = get_oauth_client(old_token_set.provider)
    if not client:
        return JSONResponse({"error": "OAuth provider not found"}, status_code=500)
    
    # Refresh tokens (with rotation)
    new_token_set = await client.refresh_tokens(refresh_token)
    if not new_token_set:
        return JSONResponse({"error": "Failed to refresh token"}, status_code=401)
    
    # Rotate: invalidate old, store new
    token_store.rotate_refresh_token(refresh_token, new_token_set)
    
    logger.debug(f"Tokens refreshed for user {new_token_set.username}")
    
    return JSONResponse({
        "access_token": new_token_set.access_token,
        "token_type": "Bearer",
        "expires_in": int(new_token_set.expires_at - time.time()),
        "refresh_token": new_token_set.refresh_token,
        "scope": new_token_set.scope
    })


async def auth_revoke(request: Request) -> JSONResponse:
    """
    Revoke an access or refresh token.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    try:
        body = await request.json()
        token = body.get("token")
    except Exception:
        # Also accept token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        else:
            return JSONResponse({"error": "Token required"}, status_code=400)
    
    if not token:
        return JSONResponse({"error": "token is required"}, status_code=400)
    
    # Get token data to find provider
    token_set = token_store.get_token(token) or token_store.get_token_by_refresh(token)
    
    if token_set:
        client = get_oauth_client(token_set.provider)
        if client:
            await client.revoke_token(token)
    else:
        # Still try to revoke locally
        token_store.revoke_token(token)
    
    return JSONResponse({"success": True, "message": "Token revoked"})


async def auth_status(request: Request) -> JSONResponse:
    """
    Check authentication status and token validity.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({
            "auth_enabled": False,
            "oauth_version": "2.1"
        })
    
    auth_header = request.headers.get("Authorization", "")
    token_set = validate_bearer_token(auth_header)
    
    if token_set:
        return JSONResponse({
            "auth_enabled": True,
            "oauth_version": "2.1",
            "authenticated": True,
            "provider": token_set.provider,
            "user": token_set.username,
            "email": token_set.email,
            "expires_at": token_set.expires_at,
            "expires_in": int(token_set.expires_at - time.time()),
            "scope": token_set.scope
        })
    
    # Include client_id in unauthenticated response for VS Code users
    oauth_config = get_oauth_config(OAUTH_PROVIDER)
    client_id = oauth_config.client_id if oauth_config else None
    
    return JSONResponse({
        "auth_enabled": True,
        "oauth_version": "2.1",
        "authenticated": False,
        "login_url": "/auth/login",
        "providers": [OAUTH_PROVIDER],
        "client_id": client_id,
        "client_id_hint": f"Use this Client ID when connecting from VS Code: {client_id}" if client_id else None
    })


async def auth_userinfo(request: Request) -> JSONResponse:
    """
    Get current user information (OpenID Connect userinfo endpoint style).
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    auth_header = request.headers.get("Authorization", "")
    token_set = validate_bearer_token(auth_header)
    
    if not token_set:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    return JSONResponse({
        "sub": token_set.user_id,
        "preferred_username": token_set.username,
        "email": token_set.email,
        "groups": token_set.groups
    })


async def auth_logout(request: Request) -> JSONResponse:
    """
    Logout - revoke current token.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        token_store.revoke_token(token)
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
        "auth_enabled": OAUTH_ENABLED,
        "oauth_version": "2.1" if OAUTH_ENABLED else None
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
        if OAUTH_ENABLED:
            # Extract Authorization header
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()
            
            # Validate token using OAuth 2.1 module
            token_set = validate_bearer_token(auth_header)
            
            if not token_set:
                response = JSONResponse(
                    {"error": "Unauthorized", "login_url": "/auth/login"},
                    status_code=401
                )
                await response(scope, receive, send)
                return
            
            # Check authorization using OAuth 2.1 client
            if oauth_client and not oauth_client.is_user_authorized(token_set):
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
    # Create event store for resumability
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        try:
            event_store = RedisEventStore(
                redis_url=redis_url,
                max_events_per_stream=1000,
                event_ttl_seconds=3600
            )
            logger.info(f"Using RedisEventStore connected to {redis_url}")
        except ImportError:
            logger.warning("Redis configured but 'redis' package not installed. Falling back to InMemoryEventStore.")
            event_store = InMemoryEventStore(
                max_events_per_stream=1000,
                event_ttl_seconds=3600
            )
        except Exception as e:
            logger.error(f"Failed to initialize RedisEventStore: {e}. Falling back to InMemoryEventStore.")
            event_store = InMemoryEventStore(
                max_events_per_stream=1000,
                event_ttl_seconds=3600
            )
    else:
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
        
        # OAuth 2.1 Authorization Server endpoints (RFC 8414)
        Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/{path:path}", oauth_protected_resource, methods=["GET"]),
        Route("/authorize", oauth_authorize, methods=["GET"]),
        Route("/token", oauth_token, methods=["POST"]),
        
        # OAuth client endpoints (legacy)
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
    logger.info(f"OAuth 2.1: {'Enabled (' + OAUTH_PROVIDER + ')' if OAUTH_ENABLED else 'Disabled'}")
    logger.info("=" * 60)
    logger.info("Session Management: StreamableHTTPSessionManager")
    logger.info("Resumability: Enabled (InMemoryEventStore)")
    logger.info("=" * 60)
    logger.info("Endpoints:")
    logger.info("  /mcp    - MCP Streamable HTTP endpoint")
    logger.info("  /health - Health check")
    logger.info("  /tools  - List available tools")
    logger.info("  /execute - Direct tool execution")
    if OAUTH_ENABLED:
        logger.info("  /.well-known/oauth-authorization-server - OAuth metadata")
        logger.info("  /authorize - OAuth authorization endpoint")
        logger.info("  /token     - OAuth token endpoint")
        logger.info("  /auth/*    - OAuth client endpoints")
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
