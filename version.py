"""
GraphQL MCP Server Version Information

Changelog:
- v1.3.0: Added OAuth 2.1 authentication with PKCE support (GitHub, Google, Azure)
          Added TLS support with Traefik and Let's Encrypt (Cloudflare DNS validation)
- v1.2.0: Stateful MCP server with StreamableHTTPSessionManager
- v1.1.0: Added epoch_to_readable tool
- v1.0.0: Initial release with GraphQL introspection, query, mutation tools
"""

__version__ = "1.3.0"
__version_info__ = (1, 3, 0)
__author__ = "GraphQL MCP Server Contributors"
__license__ = "MIT"

# MCP Protocol version supported
MCP_PROTOCOL_VERSION = "2024-11-05"

# Server identification
SERVER_NAME = "graphql-mcp-server"
SERVER_DESCRIPTION = "MCP server for GraphQL API interaction"
