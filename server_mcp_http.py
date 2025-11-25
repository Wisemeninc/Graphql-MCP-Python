"""
GraphQL MCP Server with Streamable HTTP Transport
Implements the MCP protocol over HTTP with SSE support for VS Code integration
"""

import os
import json
import logging
import asyncio
import uuid
from typing import Any, Optional
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import get_introspection_query, build_client_schema, print_schema
from dotenv import load_dotenv
import uvicorn

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


# Tool definitions
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


# HTTP Endpoints

async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "server": SERVER_NAME,
        "version": SERVER_VERSION
    })


async def mcp_post_endpoint(request: Request) -> Response:
    """
    Main MCP endpoint - handles POST requests with JSON-RPC messages
    This is the Streamable HTTP transport endpoint
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"POST request from {client_ip}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    
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
    session_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    sse_connections[session_id] = queue
    
    logger.info(f"SSE connection established: session={session_id}, client={client_ip}")
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
    return JSONResponse({"tools": get_tools()})


async def execute_tool_endpoint(request: Request) -> JSONResponse:
    """Execute a tool - convenience endpoint"""
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


# CORS middleware
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"]
    )
]

# Create Starlette app with all routes
app = Starlette(
    debug=True,
    routes=[
        # MCP protocol endpoints
        Route("/", mcp_post_endpoint, methods=["POST"]),
        Route("/", mcp_sse_endpoint, methods=["GET"]),
        Route("/sse", mcp_sse_endpoint, methods=["GET"]),
        Route("/messages", mcp_messages_endpoint, methods=["POST"]),
        
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
    logger.info("=" * 60)
    logger.info("Available endpoints:")
    logger.info("  POST /          - MCP JSON-RPC endpoint")
    logger.info("  GET  /          - SSE endpoint")
    logger.info("  GET  /sse       - SSE endpoint (alias)")
    logger.info("  GET  /health    - Health check")
    logger.info("  GET  /tools     - List tools")
    logger.info("  POST /execute   - Execute tool directly")
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
