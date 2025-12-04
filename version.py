"""
GraphQL MCP Server Version Information

Changelog:
- v1.5.0: Added query and logon file logging (queries.log, logons.log)
          Added ip_info tool (ip-api.com, free, no API key)
          Added web_search tool (DuckDuckGo via ddgs package)
          Removed geo_location and ip_timezone tools (required API keys)
- v1.4.0: OAuth 2.1 Authorization Server (RFC 8414, RFC 9728) for MCP client auth
          Added /.well-known/oauth-authorization-server metadata endpoint
          Added /.well-known/oauth-protected-resource endpoint
          Added /authorize and /token endpoints for standard OAuth flows
          Proxy headers support for proper HTTPS URL generation behind Traefik
- v1.3.0: Added OAuth 2.1 authentication with PKCE support (GitHub, Google, Azure)
          Added TLS support with Traefik and Let's Encrypt (Cloudflare DNS validation)
- v1.2.0: Stateful MCP server with StreamableHTTPSessionManager
- v1.1.0: Added epoch_to_readable tool
- v1.0.0: Initial release with GraphQL introspection, query, mutation tools
"""

__version__ = "1.5.0"
__version_info__ = (1, 5, 0)
__author__ = "GraphQL MCP Server Contributors"
__license__ = "MIT"

# MCP Protocol version supported
MCP_PROTOCOL_VERSION = "2024-11-05"

# Server identification
SERVER_NAME = "graphql-mcp-server"
SERVER_DESCRIPTION = "MCP server for GraphQL API interaction"
