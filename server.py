"""
GraphQL MCP Server
Provides tools for LLMs to interact with GraphQL endpoints
"""

import os
import json
import logging
from typing import Any, Optional
from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import get_introspection_query, build_client_schema, print_schema
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio
from dotenv import load_dotenv

# Import version info
try:
    from version import __version__, SERVER_NAME
except ImportError:
    __version__ = "1.0.0"
    SERVER_NAME = "graphql-mcp-server"

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server
server = Server(SERVER_NAME)

# Global GraphQL client
graphql_client: Optional[Client] = None


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
        
        # Additional headers from environment
        custom_headers = os.getenv("GRAPHQL_HEADERS")
        if custom_headers:
            try:
                headers.update(json.loads(custom_headers))
            except json.JSONDecodeError:
                logger.warning("Invalid GRAPHQL_HEADERS format, skipping")
        
        transport = AIOHTTPTransport(url=endpoint, headers=headers)
        # Don't fetch schema automatically - some APIs have compatibility issues
        graphql_client = Client(transport=transport, fetch_schema_from_transport=False)
    
    return graphql_client


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available GraphQL tools"""
    return [
        Tool(
            name="graphql_introspection",
            description="Perform GraphQL introspection to discover the schema, types, queries, mutations, and fields available in the GraphQL API",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="graphql_query",
            description="Execute a GraphQL query against the configured endpoint. Returns both the query used and the result data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The GraphQL query to execute (without 'query' keyword prefix unless using operation names)"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Optional variables for the GraphQL query as a JSON object",
                        "default": {}
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
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
                        "description": "Optional variables for the GraphQL mutation as a JSON object",
                        "default": {}
                    }
                },
                "required": ["mutation"]
            }
        ),
        Tool(
            name="graphql_get_schema",
            description="Get the human-readable GraphQL schema in SDL (Schema Definition Language) format",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls"""
    try:
        if name == "graphql_introspection":
            return await handle_introspection()
        elif name == "graphql_query":
            return await handle_query(arguments)
        elif name == "graphql_mutation":
            return await handle_mutation(arguments)
        elif name == "graphql_get_schema":
            return await handle_get_schema()
        else:
            return [TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
    except Exception as e:
        logger.error(f"Error executing tool {name}: {str(e)}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"Error: {str(e)}"
        )]


async def handle_introspection() -> list[TextContent]:
    """Perform GraphQL introspection"""
    client = get_graphql_client()
    
    introspection_query = get_introspection_query()
    
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    response = {
        "query_used": "GraphQL Introspection Query",
        "result": result
    }
    
    return [TextContent(
        type="text",
        text=json.dumps(response, indent=2)
    )]


async def handle_get_schema() -> list[TextContent]:
    """Get GraphQL schema in SDL format"""
    client = get_graphql_client()
    
    introspection_query = get_introspection_query()
    
    async with client as session:
        result = await session.execute(gql(introspection_query))
    
    # Build schema from introspection result
    schema = build_client_schema(result)
    schema_sdl = print_schema(schema)
    
    response = {
        "query_used": "GraphQL Introspection Query (converted to SDL)",
        "result": {
            "schema": schema_sdl
        }
    }
    
    return [TextContent(
        type="text",
        text=json.dumps(response, indent=2)
    )]


async def handle_query(arguments: dict) -> list[TextContent]:
    """Execute a GraphQL query"""
    query_str = arguments.get("query", "")
    variables = arguments.get("variables", {})
    
    if not query_str:
        return [TextContent(
            type="text",
            text="Error: query parameter is required"
        )]
    
    client = get_graphql_client()
    
    # Parse and execute query
    query = gql(query_str)
    
    async with client as session:
        result = await session.execute(query, variable_values=variables)
    
    response = {
        "query_used": query_str,
        "variables": variables if variables else None,
        "result": result
    }
    
    return [TextContent(
        type="text",
        text=json.dumps(response, indent=2)
    )]


async def handle_mutation(arguments: dict) -> list[TextContent]:
    """Execute a GraphQL mutation"""
    mutation_str = arguments.get("mutation", "")
    variables = arguments.get("variables", {})
    
    if not mutation_str:
        return [TextContent(
            type="text",
            text="Error: mutation parameter is required"
        )]
    
    client = get_graphql_client()
    
    # Parse and execute mutation
    mutation = gql(mutation_str)
    
    async with client as session:
        result = await session.execute(mutation, variable_values=variables)
    
    response = {
        "mutation_used": mutation_str,
        "variables": variables if variables else None,
        "result": result
    }
    
    return [TextContent(
        type="text",
        text=json.dumps(response, indent=2)
    )]


async def main():
    """Run the MCP server using stdio transport"""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
