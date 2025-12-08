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
import asyncio
import contextvars
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

# ============================================================================
# Query and Logon File Logging
# ============================================================================

# Log directory configuration
LOG_DIR = os.getenv("LOG_DIR", "/app/logs")
QUERY_LOG_FILE = os.path.join(LOG_DIR, "queries.log")
LOGON_LOG_FILE = os.path.join(LOG_DIR, "logons.log")
QUERY_LOG_ENABLED = os.getenv("QUERY_LOG_ENABLED", "true").lower() == "true"
LOGON_LOG_ENABLED = os.getenv("LOGON_LOG_ENABLED", "true").lower() == "true"

# Create log directory if it doesn't exist
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create log directory {LOG_DIR}: {e}")

# Setup query logger
query_logger = logging.getLogger("query_log")
query_logger.setLevel(logging.INFO)
query_logger.propagate = False  # Don't propagate to root logger

# Setup logon logger
logon_logger = logging.getLogger("logon_log")
logon_logger.setLevel(logging.INFO)
logon_logger.propagate = False

# Add file handlers if logging is enabled
if QUERY_LOG_ENABLED:
    try:
        query_handler = logging.FileHandler(QUERY_LOG_FILE)
        query_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        query_logger.addHandler(query_handler)
        logger.info(f"Query logging enabled: {QUERY_LOG_FILE}")
    except Exception as e:
        logger.warning(f"Could not setup query log file: {e}")
        QUERY_LOG_ENABLED = False

if LOGON_LOG_ENABLED:
    try:
        logon_handler = logging.FileHandler(LOGON_LOG_FILE)
        logon_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logon_logger.addHandler(logon_handler)
        logger.info(f"Logon logging enabled: {LOGON_LOG_FILE}")
    except Exception as e:
        logger.warning(f"Could not setup logon log file: {e}")
        LOGON_LOG_ENABLED = False


def log_query(tool_name: str, arguments: dict, client_ip: str = None, user: str = None):
    """Log a query/tool call to the query log file."""
    if not QUERY_LOG_ENABLED:
        return
    try:
        # Truncate large arguments for logging
        args_str = json.dumps(arguments)[:500] if arguments else "{}"
        log_entry = f"TOOL={tool_name} | IP={client_ip or 'unknown'} | USER={user or 'anonymous'} | ARGS={args_str}"
        query_logger.info(log_entry)
    except Exception as e:
        logger.debug(f"Failed to log query: {e}")


def log_logon(event: str, user: str = None, provider: str = None, client_ip: str = None, success: bool = True, details: str = None):
    """Log a logon event to the logon log file."""
    if not LOGON_LOG_ENABLED:
        return
    try:
        status = "SUCCESS" if success else "FAILED"
        log_entry = f"EVENT={event} | STATUS={status} | USER={user or 'unknown'} | PROVIDER={provider or 'N/A'} | IP={client_ip or 'unknown'}"
        if details:
            log_entry += f" | DETAILS={details}"
        logon_logger.info(log_entry)
    except Exception as e:
        logger.debug(f"Failed to log logon: {e}")

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

# Static API Token Configuration (alternative to OAuth)
# Format: API_TOKENS="token1:user1,token2:user2" or just "token1,token2" for anonymous
API_TOKENS_ENABLED = os.getenv("API_TOKENS_ENABLED", "false").lower() == "true"
API_TOKENS: dict[str, str] = {}  # token -> username mapping

if API_TOKENS_ENABLED:
    tokens_str = os.getenv("API_TOKENS", "")
    if tokens_str:
        for token_entry in tokens_str.split(","):
            token_entry = token_entry.strip()
            if ":" in token_entry:
                # Format: token:username
                token, username = token_entry.split(":", 1)
                API_TOKENS[token.strip()] = username.strip()
            else:
                # Just token, use "api-user" as default username
                API_TOKENS[token_entry] = "api-user"
        logger.info(f"API token authentication enabled with {len(API_TOKENS)} token(s)")
    else:
        logger.warning("API_TOKENS_ENABLED is true but no API_TOKENS configured")
        API_TOKENS_ENABLED = False


def validate_api_token(auth_header: str) -> tuple[bool, str | None]:
    """
    Validate a static API token from Authorization header.
    Returns (is_valid, username) tuple.
    """
    if not API_TOKENS_ENABLED or not auth_header:
        return False, None
    
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token in API_TOKENS:
            return True, API_TOKENS[token]
    
    return False, None

# CIMD (Client ID Metadata Document) Configuration
CIMD_ENABLED = os.getenv("CIMD_ENABLED", "true").lower() == "true"
CIMD_CACHE_TTL = int(os.getenv("CIMD_CACHE_TTL", "86400"))  # 24 hours default
CIMD_MAX_SIZE = int(os.getenv("CIMD_MAX_SIZE", "10240"))  # 10KB max
CIMD_TIMEOUT = int(os.getenv("CIMD_TIMEOUT", "5"))  # 5 seconds timeout

# In-memory cache for CIMD documents
_cimd_cache: dict[str, tuple[dict, float]] = {}

# Global GraphQL client
graphql_client: Optional[Client] = None

# Context variables to store client info for MCP tool calls
_client_ip_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar('client_ip', default=None)
_client_user_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar('client_user', default=None)


def get_client_ip_from_scope(scope: dict) -> Optional[str]:
    """
    Extract the client's real IP address from ASGI scope.
    Respects X-Forwarded-For and X-Real-IP headers from reverse proxies.
    """
    headers = dict(scope.get("headers", []))
    
    # Check for X-Forwarded-For header (comma-separated list, first is client)
    forwarded_for = headers.get(b"x-forwarded-for", b"").decode()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = headers.get(b"x-real-ip", b"").decode()
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct connection IP from scope
    client = scope.get("client")
    if client and len(client) >= 1:
        return client[0]
    
    return None


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


# NTP Configuration
NTP_SERVER = os.getenv("NTP_SERVER", "dk.pool.ntp.org")
NTP_TIMEOUT = float(os.getenv("NTP_TIMEOUT", "5.0"))

# IP Info Configuration (ip-api.com - free, no API key required)
IP_API_URL = "http://ip-api.com/json"
IP_API_TIMEOUT = float(os.getenv("IP_API_TIMEOUT", "10.0"))


async def handle_ntp_time(
    server: str = None,
    include_offset: bool = True
) -> dict:
    """
    Get accurate time from NTP server.
    
    Uses dk.pool.ntp.org by default (configurable via NTP_SERVER env var).
    Returns NTP time, local time, and offset between them.
    """
    import socket
    import struct
    
    ntp_server = server or NTP_SERVER
    
    # NTP packet format constants
    NTP_DELTA = 2208988800  # Seconds between 1900 and 1970
    
    try:
        # Create NTP request packet
        # LI=0, VN=3, Mode=3 (client), Stratum=0, Poll=0, Precision=0
        packet = b'\x1b' + 47 * b'\0'
        
        # Record local time before request
        local_before = time.time()
        
        # Create UDP socket and send request
        loop = asyncio.get_event_loop()
        
        def sync_ntp_request():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(NTP_TIMEOUT)
            try:
                sock.sendto(packet, (ntp_server, 123))
                data, _ = sock.recvfrom(1024)
                return data
            finally:
                sock.close()
        
        # Run blocking socket operation in executor
        data = await loop.run_in_executor(None, sync_ntp_request)
        
        # Record local time after response
        local_after = time.time()
        
        # Parse NTP response
        if len(data) < 48:
            raise ValueError("Invalid NTP response (too short)")
        
        # Extract transmit timestamp (bytes 40-47)
        ntp_seconds = struct.unpack('!I', data[40:44])[0]
        ntp_fraction = struct.unpack('!I', data[44:48])[0]
        
        # Convert NTP time to Unix epoch
        ntp_time = ntp_seconds - NTP_DELTA + (ntp_fraction / (2**32))
        
        # Calculate round-trip delay and offset
        round_trip = local_after - local_before
        local_time = (local_before + local_after) / 2
        offset = ntp_time - local_time
        
        # Format times
        ntp_utc = time.gmtime(ntp_time)
        local_utc = time.gmtime(local_time)
        
        result = {
            "ntp_server": ntp_server,
            "ntp_time": {
                "epoch": ntp_time,
                "iso8601": time.strftime("%Y-%m-%dT%H:%M:%S", ntp_utc) + f".{int((ntp_time % 1) * 1000):03d}Z",
                "readable": time.strftime("%Y-%m-%d %H:%M:%S", ntp_utc) + f".{int((ntp_time % 1) * 1000):03d} UTC"
            },
            "local_time": {
                "epoch": local_time,
                "iso8601": time.strftime("%Y-%m-%dT%H:%M:%S", local_utc) + f".{int((local_time % 1) * 1000):03d}Z",
                "readable": time.strftime("%Y-%m-%d %H:%M:%S", local_utc) + f".{int((local_time % 1) * 1000):03d} UTC"
            },
            "round_trip_ms": round(round_trip * 1000, 2),
            "status": "success"
        }
        
        if include_offset:
            result["offset"] = {
                "seconds": round(offset, 6),
                "milliseconds": round(offset * 1000, 3),
                "description": f"Local clock is {abs(offset * 1000):.2f}ms {'behind' if offset > 0 else 'ahead of'} NTP"
            }
        
        logger.info(f"NTP time retrieved from {ntp_server}, offset: {offset*1000:.2f}ms")
        return result
        
    except socket.timeout:
        logger.warning(f"NTP request to {ntp_server} timed out")
        return {
            "ntp_server": ntp_server,
            "status": "error",
            "error": f"Timeout connecting to NTP server (>{NTP_TIMEOUT}s)"
        }
    except socket.gaierror as e:
        logger.error(f"NTP DNS resolution failed for {ntp_server}: {e}")
        return {
            "ntp_server": ntp_server,
            "status": "error",
            "error": f"DNS resolution failed: {str(e)}"
        }
    except Exception as e:
        logger.error(f"NTP error: {e}", exc_info=True)
        return {
            "ntp_server": ntp_server,
            "status": "error",
            "error": str(e)
        }


async def handle_ip_info(ip_address: str = None) -> dict:
    """
    Get IP information including timezone and location using ip-api.com.
    
    This is a free API that doesn't require an API key.
    Rate limit: 45 requests per minute from an IP address.
    
    Returns:
    - IP address
    - Location (country, region, city, coordinates)
    - Timezone information with current local time
    - ISP and organization info
    """
    try:
        # Build the API URL
        # ip-api.com format: http://ip-api.com/json/{ip}?fields=...
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,offset,isp,org,as,query"
        
        if ip_address:
            url = f"{IP_API_URL}/{ip_address}"
        else:
            url = IP_API_URL
        
        timeout = aiohttp.ClientTimeout(total=IP_API_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                params={"fields": fields},
                headers={
                    "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
                    "Accept": "application/json"
                }
            ) as resp:
                
                if resp.status == 429:
                    return {
                        "status": "error",
                        "error": "Rate limit exceeded (45 req/min). Please wait before retrying.",
                        "ip": ip_address
                    }
                
                if resp.status != 200:
                    return {
                        "status": "error",
                        "error": f"API returned status {resp.status}",
                        "ip": ip_address
                    }
                
                data = await resp.json()
                
                # Check API-level status
                if data.get("status") == "fail":
                    return {
                        "status": "error",
                        "error": data.get("message", "Unknown error"),
                        "ip": ip_address
                    }
                
                # Get current time in the timezone
                tz_name = data.get("timezone", "UTC")
                offset_seconds = data.get("offset", 0)
                
                # Calculate current time in timezone
                utc_now = time.time()
                local_time = utc_now + offset_seconds
                local_utc = time.gmtime(local_time)
                
                # Format offset as ±HH:MM
                offset_hours = offset_seconds // 3600
                offset_mins = abs(offset_seconds % 3600) // 60
                offset_str = f"{'+' if offset_seconds >= 0 else '-'}{abs(offset_hours):02d}:{offset_mins:02d}"
                
                result = {
                    "status": "success",
                    "ip": data.get("query"),
                    "timezone": {
                        "name": tz_name,
                        "offset_seconds": offset_seconds,
                        "offset": offset_str,
                        "current_time": {
                            "iso8601": time.strftime("%Y-%m-%dT%H:%M:%S", local_utc) + offset_str.replace(":", ""),
                            "readable": time.strftime("%Y-%m-%d %H:%M:%S", local_utc) + f" ({tz_name})",
                            "date": time.strftime("%Y-%m-%d", local_utc),
                            "time": time.strftime("%H:%M:%S", local_utc),
                            "unix_utc": utc_now
                        }
                    },
                    "location": {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "region_code": data.get("region"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon")
                    },
                    "network": {
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as")
                    }
                }
                
                # Add maps URL if coordinates available
                if data.get("lat") and data.get("lon"):
                    result["location"]["maps_url"] = f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}"
                
                logger.info(f"IP info retrieved: {data.get('query')} -> {tz_name} ({data.get('city')}, {data.get('country')})")
                return result
                
    except asyncio.TimeoutError:
        logger.warning(f"IP API request timed out for IP: {ip_address}")
        return {
            "status": "error",
            "error": f"Request timed out (>{IP_API_TIMEOUT}s)",
            "ip": ip_address
        }
    except Exception as e:
        logger.error(f"IP API error: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "ip": ip_address
        }


# Web Search Configuration
WEB_SEARCH_MAX_RESULTS = int(os.getenv("WEB_SEARCH_MAX_RESULTS", "10"))
WEB_SEARCH_REGION = os.getenv("WEB_SEARCH_REGION", "wt-wt")  # wt-wt = worldwide
WEB_SEARCH_SAFESEARCH = os.getenv("WEB_SEARCH_SAFESEARCH", "moderate")


async def handle_web_search(query: str, max_results: int = None) -> dict:
    """
    Search the web using DuckDuckGo.
    
    Returns search results with titles, URLs, and snippets.
    No API key required.
    """
    if not query or not query.strip():
        return {
            "status": "error",
            "error": "Search query cannot be empty"
        }
    
    max_results = max_results or WEB_SEARCH_MAX_RESULTS
    # Cap at 25 results
    max_results = min(max_results, 25)
    
    try:
        # Use new ddgs package (duckduckgo_search was renamed)
        from ddgs import DDGS
        
        loop = asyncio.get_event_loop()
        
        def sync_search():
            with DDGS() as ddgs:
                return list(ddgs.text(
                    query=query.strip(),
                    region=WEB_SEARCH_REGION,
                    safesearch=WEB_SEARCH_SAFESEARCH,
                    max_results=max_results
                ))
        
        # Run blocking search in executor
        results = await loop.run_in_executor(None, sync_search)
        
        if not results:
            return {
                "status": "success",
                "query": query,
                "results_count": 0,
                "results": [],
                "message": "No results found"
            }
        
        # Format results
        formatted_results = []
        for idx, result in enumerate(results, 1):
            formatted_results.append({
                "position": idx,
                "title": result.get("title", "No title"),
                "url": result.get("href", ""),
                "snippet": result.get("body", "No description available")
            })
        
        logger.info(f"Web search completed: '{query}' -> {len(formatted_results)} results")
        
        return {
            "status": "success",
            "query": query,
            "results_count": len(formatted_results),
            "results": formatted_results
        }
        
    except ImportError:
        logger.error("duckduckgo-search package not installed")
        return {
            "status": "error",
            "error": "Web search not available: duckduckgo-search package not installed"
        }
    except Exception as e:
        logger.error(f"Web search error: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "query": query
        }


# ============================================================================
# OAuth 2.1 Authorization Server Endpoints (RFC 8414)
# ============================================================================

def get_client_ip(request: Request) -> str:
    """
    Extract the client's real IP address from the request.
    Respects X-Forwarded-For and X-Real-IP headers from reverse proxies.
    """
    # Check for X-Forwarded-For header (comma-separated list, first is client)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct connection IP
    if request.client and request.client.host:
        return request.client.host
    
    return None


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


# ============================================================================
# Client ID Metadata Document (CIMD) Support
# Per: https://www.ietf.org/archive/id/draft-parecki-oauth-client-id-metadata-document-03.html
# ============================================================================

def is_cimd_client_id(client_id: str) -> bool:
    """
    Check if client_id is a CIMD URL (starts with https:// and has a path).
    Per spec: client_id MUST be an HTTPS URL with a path component.
    """
    if not client_id:
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(client_id)
        return (
            parsed.scheme == "https" and 
            parsed.netloc and 
            parsed.path and 
            parsed.path != "/"
        )
    except Exception:
        return False


def is_safe_cimd_url(url: str) -> bool:
    """
    Validate URL is safe to fetch (prevent SSRF attacks).
    Block internal/private IP ranges and localhost.
    """
    try:
        from urllib.parse import urlparse
        import ipaddress
        import socket
        
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        
        # Block localhost variations
        if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return False
        
        # Try to resolve hostname and check if it's a private IP
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return False
        except socket.gaierror:
            # Can't resolve - might be valid, let the fetch fail
            pass
        
        return True
    except Exception:
        return False


async def fetch_cimd_metadata(client_id_url: str) -> Optional[dict]:
    """
    Fetch Client ID Metadata Document from the client_id URL.
    
    Per the spec:
    - client_id in the document MUST exactly match the URL
    - Document must contain redirect_uris
    - Must be valid JSON with size limits
    
    Returns validated metadata dict or None if invalid.
    """
    global _cimd_cache
    
    # Check cache first
    if client_id_url in _cimd_cache:
        cached_data, cached_time = _cimd_cache[client_id_url]
        if time.time() - cached_time < CIMD_CACHE_TTL:
            logger.debug(f"CIMD cache hit for: {client_id_url}")
            return cached_data
    
    # Validate URL is safe
    if not is_safe_cimd_url(client_id_url):
        logger.warning(f"CIMD URL blocked (SSRF protection): {client_id_url}")
        return None
    
    try:
        timeout = aiohttp.ClientTimeout(total=CIMD_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                client_id_url,
                headers={"Accept": "application/json"},
                ssl=None if SSL_VERIFY else False
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"CIMD fetch failed: {resp.status} for {client_id_url}")
                    return None
                
                # Check content length
                content_length = resp.headers.get("Content-Length")
                if content_length and int(content_length) > CIMD_MAX_SIZE:
                    logger.warning(f"CIMD too large: {content_length} bytes for {client_id_url}")
                    return None
                
                # Read with size limit
                content = await resp.read()
                if len(content) > CIMD_MAX_SIZE:
                    logger.warning(f"CIMD too large: {len(content)} bytes for {client_id_url}")
                    return None
                
                metadata = json.loads(content.decode('utf-8'))
                
                # Validate required fields per spec
                if not isinstance(metadata, dict):
                    logger.warning(f"CIMD not a JSON object: {client_id_url}")
                    return None
                
                # client_id MUST exactly match the URL
                if metadata.get("client_id") != client_id_url:
                    logger.warning(f"CIMD client_id mismatch: expected {client_id_url}, got {metadata.get('client_id')}")
                    return None
                
                # redirect_uris is required
                if "redirect_uris" not in metadata or not isinstance(metadata["redirect_uris"], list):
                    logger.warning(f"CIMD missing redirect_uris: {client_id_url}")
                    return None
                
                # Cache the valid metadata
                _cimd_cache[client_id_url] = (metadata, time.time())
                logger.info(f"CIMD fetched and cached: {client_id_url} ({metadata.get('client_name', 'Unknown')})")
                
                return metadata
                
    except asyncio.TimeoutError:
        logger.warning(f"CIMD fetch timeout: {client_id_url}")
        return None
    except json.JSONDecodeError:
        logger.warning(f"CIMD invalid JSON: {client_id_url}")
        return None
    except Exception as e:
        logger.error(f"CIMD fetch error for {client_id_url}: {e}")
        return None


def validate_cimd_redirect_uri(metadata: dict, redirect_uri: str) -> bool:
    """
    Validate that the redirect_uri is in the client's allowed list.
    Per spec: exact string match required.
    """
    allowed_uris = metadata.get("redirect_uris", [])
    return redirect_uri in allowed_uris


async def oauth_metadata(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414)
    Returns server metadata for MCP client discovery.
    
    Supports:
    - Dynamic Client Registration (RFC 7591)
    - Client ID Metadata Documents (CIMD) per draft-parecki-oauth-client-id-metadata-document
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
        metadata["registration_endpoint"] = f"{base_url}/register"
        
        # Advertise CIMD support per draft-parecki-oauth-client-id-metadata-document
        # This tells MCP clients they can use URL-based client_ids
        if CIMD_ENABLED:
            metadata["client_id_metadata_document_supported"] = True
        
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


async def oauth_register(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Dynamic Client Registration (RFC 7591)
    
    Allows MCP clients (like VS Code) to automatically obtain a client_id
    without user interaction. This is the recommended way per MCP spec.
    
    Since we're proxying to GitHub OAuth, we return our shared public client_id.
    """
    if not OAUTH_ENABLED:
        return JSONResponse({"error": "OAuth authentication is not enabled"}, status_code=400)
    
    oauth_config = get_oauth_config(OAUTH_PROVIDER)
    if not oauth_config or not oauth_config.client_id:
        return JSONResponse({"error": "server_error", "error_description": "OAuth not configured"}, status_code=500)
    
    try:
        # Parse registration request (may be empty for simple clients)
        try:
            body = await request.json()
        except Exception:
            body = {}
        
        # Get requested redirect URIs (VS Code will provide these)
        redirect_uris = body.get("redirect_uris", [])
        client_name = body.get("client_name", "MCP Client")
        
        # For a proxy setup to GitHub, we return our shared client credentials
        # In a full implementation, you'd generate unique client_ids per registration
        base_url = get_external_base_url(request)
        
        # Return client registration response per RFC 7591
        response = {
            "client_id": oauth_config.client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris if redirect_uris else [f"{base_url}/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",  # Public client
            # Additional metadata
            "client_id_issued_at": int(time.time()),
            # No expiration - client_id is permanent
        }
        
        logger.info(f"Dynamic client registration: {client_name}")
        return JSONResponse(response, status_code=201)
        
    except Exception as e:
        logger.error(f"Client registration error: {e}")
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)


async def oauth_authorize(request: Request) -> Response:
    """
    OAuth 2.1 Authorization endpoint.
    Proxies to the configured OAuth provider (e.g., GitHub).
    
    Supports:
    - Traditional client_id (string)
    - CIMD client_id (HTTPS URL) per draft-parecki-oauth-client-id-metadata-document
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
    
    # Handle CIMD (Client ID Metadata Document) - client_id is an HTTPS URL
    client_metadata = None
    if CIMD_ENABLED and client_id and is_cimd_client_id(client_id):
        logger.info(f"CIMD client_id detected: {client_id}")
        client_metadata = await fetch_cimd_metadata(client_id)
        
        if not client_metadata:
            return JSONResponse({
                "error": "invalid_client",
                "error_description": "Failed to fetch or validate client metadata from URL"
            }, status_code=400)
        
        # Validate redirect_uri against CIMD
        if redirect_uri and not validate_cimd_redirect_uri(client_metadata, redirect_uri):
            return JSONResponse({
                "error": "invalid_request",
                "error_description": f"redirect_uri not in client's allowed list"
            }, status_code=400)
        
        logger.info(f"CIMD validated for client: {client_metadata.get('client_name', 'Unknown')}")
    
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
        "client_id": client_id,
        "cimd_client_name": client_metadata.get("client_name") if client_metadata else None,
        "cimd_validated": client_metadata is not None
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
        # Log failed authorization
        client_ip = get_client_ip(request)
        log_logon(
            event="AUTH_DENIED",
            user=token_set.username,
            provider=auth_request.provider,
            client_ip=client_ip,
            success=False,
            details="User not authorized"
        )
        return JSONResponse({
            "error": "Forbidden",
            "message": f"User {token_set.username} is not authorized to access this server"
        }, status_code=403)
    
    # Store the token
    token_store.store_token(token_set)
    
    # Log successful authentication
    client_ip = get_client_ip(request)
    log_logon(
        event="LOGIN",
        user=token_set.username,
        provider=auth_request.provider,
        client_ip=client_ip,
        success=True
    )
    
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
    client_ip = get_client_ip(request)
    
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        # Try to get user info before revoking
        if OAUTH_ENABLED:
            token_set = validate_bearer_token(auth_header)
            user = token_set.username if token_set else "unknown"
        else:
            user = "unknown"
        
        token_store.revoke_token(token)
        
        # Log the logout
        log_logon(
            event="LOGOUT",
            user=user,
            client_ip=client_ip,
            success=True
        )
        
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
        "auth_enabled": OAUTH_ENABLED or API_TOKENS_ENABLED,
        "oauth_enabled": OAUTH_ENABLED,
        "api_tokens_enabled": API_TOKENS_ENABLED,
        "oauth_version": "2.1" if OAUTH_ENABLED else None
    })


async def list_tools_endpoint(request: Request) -> JSONResponse:
    tools = [
        {"name": "graphql_introspection", "description": "Perform GraphQL introspection"},
        {"name": "graphql_query", "description": "Execute a GraphQL query"},
        {"name": "graphql_mutation", "description": "Execute a GraphQL mutation"},
        {"name": "graphql_get_schema", "description": "Get GraphQL schema in SDL format"},
        {"name": "epoch_to_readable", "description": "Convert epoch timestamp to readable format"},
        {"name": "ntp_time", "description": "Get accurate time from NTP server (dk.pool.ntp.org)"},
        {"name": "ip_info", "description": "Get timezone and location from IP address (no API key required)"},
        {"name": "web_search", "description": "Search the web using DuckDuckGo (no API key required)"}
    ]
    return JSONResponse({"tools": tools})


async def execute_tool_endpoint(request: Request) -> JSONResponse:
    """Direct tool execution endpoint for testing"""
    try:
        body = await request.json()
        tool_name = body.get("tool")
        arguments = body.get("arguments", {})
        
        # Get client IP for geo/timezone lookups
        client_ip = get_client_ip(request)
        
        # Log the query
        log_query(tool_name, arguments, client_ip=client_ip)
        
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
        elif tool_name == "ntp_time":
            result = await handle_ntp_time(
                arguments.get("server"),
                arguments.get("include_offset", True)
            )
        elif tool_name == "ip_info":
            # Use client IP if no IP specified
            ip_to_lookup = arguments.get("ip") or client_ip
            result = await handle_ip_info(ip_to_lookup)
        elif tool_name == "web_search":
            result = await handle_web_search(
                arguments.get("query", ""),
                arguments.get("max_results")
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
            ),
            types.Tool(
                name="ntp_time",
                description="Get accurate time from NTP (Network Time Protocol) server. Returns precise UTC time from dk.pool.ntp.org and compares with local system time to show clock offset.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Optional NTP server to query (default: dk.pool.ntp.org). Examples: time.google.com, pool.ntp.org",
                            "default": "dk.pool.ntp.org"
                        },
                        "include_offset": {
                            "type": "boolean",
                            "description": "Include local clock offset calculation (default: true)",
                            "default": True
                        }
                    },
                    "required": []
                }
            ),
            types.Tool(
                name="ip_info",
                description="Get IP information including timezone, location, and network details using ip-api.com (free, no API key required). Returns timezone with current local time, country, city, coordinates, and ISP info. If no IP is provided, uses the MCP client's IP address. Rate limit: 45 requests/minute.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address to look up (e.g., '8.8.8.8'). If not provided, uses your current IP address."
                        }
                    },
                    "required": []
                }
            ),
            types.Tool(
                name="web_search",
                description="Search the web using DuckDuckGo (free, no API key required). Returns search results with titles, URLs, and snippets. Useful for finding current information, documentation, news, and general web content.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search query string"
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 10, max: 25)",
                            "default": 10
                        }
                    },
                    "required": ["query"]
                }
            )
        ]
    
    @mcp_app.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        """Handle tool calls"""
        logger.info(f"Tool call: {name}")
        logger.debug(f"Arguments: {json.dumps(arguments)[:500] if arguments else 'None'}")
        
        # Log query to file with user context
        client_ip = _client_ip_context.get()
        client_user = _client_user_context.get()
        log_query(name, arguments, client_ip=client_ip, user=client_user)
        
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
            elif name == "ntp_time":
                result = await handle_ntp_time(
                    arguments.get("server"),
                    arguments.get("include_offset", True)
                )
            elif name == "ip_info":
                # Use client IP from context if no IP specified
                ip_to_lookup = arguments.get("ip") or _client_ip_context.get()
                result = await handle_ip_info(ip_to_lookup)
            elif name == "web_search":
                query = arguments.get("query", "")
                if not query:
                    raise ValueError("query parameter is required")
                result = await handle_web_search(
                    query,
                    arguments.get("max_results")
                )
            else:
                return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
        except Exception as e:
            logger.error(f"Error executing tool {name}: {e}", exc_info=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
    
    # ========================================================================
    # System Prompts
    # ========================================================================
    
    @mcp_app.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        """List available prompts"""
        return [
            types.Prompt(
                name="graphql-assistant",
                description="System prompt for GraphQL API interaction assistant",
                arguments=[]
            ),
            types.Prompt(
                name="graphql-explorer",
                description="System prompt for exploring and discovering GraphQL schemas",
                arguments=[]
            )
        ]
    
    @mcp_app.get_prompt()
    async def get_prompt(name: str, arguments: dict[str, str] | None = None) -> types.GetPromptResult:
        """Get a specific prompt"""
        
        graphql_endpoint = os.getenv("GRAPHQL_ENDPOINT", "configured GraphQL endpoint")
        
        if name == "graphql-assistant":
            return types.GetPromptResult(
                description="GraphQL API Assistant",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""You are a GraphQL API assistant with access to a GraphQL endpoint at: {graphql_endpoint}

You have the following tools available:

## GraphQL Tools
- **graphql_introspection**: Discover the complete API schema, types, queries, and mutations. Use this FIRST to understand what's available.
- **graphql_get_schema**: Get the schema in human-readable SDL format. Useful for understanding the data model.
- **graphql_query**: Execute GraphQL queries to fetch data. Always use proper GraphQL syntax.
- **graphql_mutation**: Execute GraphQL mutations to modify data. Be careful with mutations as they change data.

## Utility Tools
- **epoch_to_readable**: Convert Unix timestamps to human-readable dates.
- **ntp_time**: Get accurate network time from NTP servers.
- **ip_info**: Get geolocation and timezone info for IP addresses.
- **web_search**: Search the web using DuckDuckGo for additional context.

## Best Practices
1. **Always introspect first**: Before querying, use graphql_introspection or graphql_get_schema to understand the available types and fields.
2. **Use proper GraphQL syntax**: Queries should be valid GraphQL. Include field selections - don't just request a type.
3. **Handle pagination**: Look for connection patterns (edges/nodes) or limit/offset arguments.
4. **Use variables**: For dynamic values, use GraphQL variables instead of string interpolation.
5. **Be specific with fields**: Only request the fields you need to minimize response size.

## Example Query Pattern
```graphql
query GetItems($limit: Int) {{
  items(limit: $limit) {{
    id
    name
    createdAt
  }}
}}
```

When the user asks about the API, start by exploring the schema to understand what's available."""
                        )
                    )
                ]
            )
        
        elif name == "graphql-explorer":
            return types.GetPromptResult(
                description="GraphQL Schema Explorer",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""You are a GraphQL schema explorer helping users understand and navigate a GraphQL API at: {graphql_endpoint}

Your primary goal is to help users discover and understand the API structure.

## Exploration Strategy
1. Start with **graphql_get_schema** to get the full SDL schema
2. Identify the main Query and Mutation types
3. Look for key entities and their relationships
4. Note any custom scalars, enums, or input types

## What to Look For
- **Root Query fields**: Entry points for reading data
- **Root Mutation fields**: Entry points for writing data
- **Types and their fields**: The data model
- **Connections/Edges**: Pagination patterns
- **Required vs optional fields**: Marked with ! in SDL
- **Arguments**: Filter, sort, and pagination options

## How to Present Information
- Summarize the main entities and their purposes
- Highlight the most useful queries for common tasks
- Explain relationships between types
- Provide example queries for key operations

When exploring, be thorough but present information in a digestible way. Focus on what the user is trying to accomplish."""
                        )
                    )
                ]
            )
        
        else:
            raise ValueError(f"Unknown prompt: {name}")
    
    return mcp_app


# ============================================================================
# Authentication Middleware for MCP Endpoint
# ============================================================================

class AuthenticatedMCPHandler:
    """Wrapper to add authentication to MCP endpoint"""
    
    def __init__(self, session_manager: StreamableHTTPSessionManager):
        self.session_manager = session_manager
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Extract and store client IP in context for tool handlers
        client_ip = get_client_ip_from_scope(scope)
        _client_ip_context.set(client_ip)
        _client_user_context.set(None)  # Default to None
        
        # Check if any authentication is required
        if OAUTH_ENABLED or API_TOKENS_ENABLED:
            # Extract Authorization header
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()
            
            # Try API token authentication first (faster, no external calls)
            if API_TOKENS_ENABLED:
                is_valid, api_user = validate_api_token(auth_header)
                if is_valid:
                    _client_user_context.set(api_user)
                    # Log API token access
                    log_logon(
                        event="API_ACCESS",
                        user=api_user,
                        provider="api-token",
                        client_ip=client_ip,
                        success=True
                    )
                    # Pass to session manager - authenticated via API token
                    await self.session_manager.handle_request(scope, receive, send)
                    return
            
            # Try OAuth authentication
            if OAUTH_ENABLED:
                token_set = validate_bearer_token(auth_header)
                
                if token_set:
                    # Store authenticated user in context
                    _client_user_context.set(token_set.username)
                    
                    # Check authorization using OAuth 2.1 client
                    if oauth_client and not oauth_client.is_user_authorized(token_set):
                        response = JSONResponse(
                            {"error": "Forbidden", "message": "User not authorized"},
                            status_code=403
                        )
                        await response(scope, receive, send)
                        return
                    
                    # Pass to session manager - authenticated via OAuth
                    await self.session_manager.handle_request(scope, receive, send)
                    return
            
            # No valid authentication found
            response = JSONResponse(
                {"error": "Unauthorized", "login_url": "/auth/login"},
                status_code=401
            )
            await response(scope, receive, send)
            return
        
        # No authentication required
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
        Route("/register", oauth_register, methods=["POST"]),
        
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
    logger.info(f"API Tokens: {'Enabled (' + str(len(API_TOKENS)) + ' tokens)' if API_TOKENS_ENABLED else 'Disabled'}")
    if OAUTH_ENABLED and CIMD_ENABLED:
        logger.info(f"CIMD: Enabled (Client ID Metadata Documents)")
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
        logger.info("  /authorize - OAuth authorization endpoint (supports CIMD)")
        logger.info("  /token     - OAuth token endpoint")
        logger.info("  /register  - Dynamic client registration (RFC 7591)")
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
