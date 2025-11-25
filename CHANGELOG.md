# Changelog

All notable changes to the GraphQL MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-25

### Added

#### Core Features
- **GraphQL Introspection Tool** (`graphql_introspection`) - Discover complete API schema, types, queries, and mutations
- **Schema Retrieval Tool** (`graphql_get_schema`) - Get human-readable schema in SDL format
- **Query Execution Tool** (`graphql_query`) - Execute GraphQL queries with variable support
- **Mutation Execution Tool** (`graphql_mutation`) - Execute GraphQL mutations with variable support
- **Query Transparency** - Every response includes the query/mutation used along with the result

#### Transport Support
- **Stdio Transport** (`server.py`) - For local MCP clients like Claude Desktop
- **HTTP/SSE Transport** (`server_http.py`) - Basic HTTP endpoints for web clients
- **MCP Streamable HTTP Transport** (`server_mcp_http.py`) - Full MCP protocol support for VS Code

#### MCP Protocol
- JSON-RPC 2.0 compliant messaging
- `initialize` / `initialized` handshake
- `tools/list` - List available tools
- `tools/call` - Execute tools
- `ping` - Connection keepalive
- Protocol version: `2024-11-05`

#### Docker Support
- `Dockerfile` - Production-ready container image
- `docker-compose.yml` - Easy deployment configuration
- `.dockerignore` - Optimized build context
- Health checks and auto-restart policies
- Non-root user for security

#### Configuration
- Environment variable configuration via `.env`
- `GRAPHQL_ENDPOINT` - Target GraphQL API URL
- `GRAPHQL_AUTH_TOKEN` - Bearer token authentication
- `GRAPHQL_HEADERS` - Custom headers (JSON format)
- `MCP_HOST` / `MCP_PORT` - Server binding options

#### Documentation
- `README.md` - Project overview and quick start
- `QUICKSTART.md` - Step-by-step setup guide
- `CLAUDE_DESKTOP.md` - Claude Desktop integration guide
- `VSCODE_INTEGRATION.md` - VS Code configuration guide
- `DOCKER_SSE_GUIDE.md` - Docker and SSE usage guide
- `API_REFERENCE.md` - Complete API documentation

#### Developer Experience
- `setup.sh` - Automated environment setup
- `run.sh` - Convenience runner script
- `test_setup.py` - Setup verification tool
- `example_client.py` - Usage examples and patterns
- CORS support for browser-based clients

### Security
- Environment-based secret management
- Bearer token authentication support
- Custom header injection for API keys
- Non-root Docker container execution
- `.gitignore` excludes sensitive files

---

## [Unreleased]

### Planned
- Subscription support for real-time GraphQL updates
- Query caching and optimization
- Rate limiting and request throttling
- API key authentication for the MCP server itself
- Metrics and monitoring endpoints
- WebSocket transport option
- Multi-endpoint configuration (single server, multiple GraphQL APIs)

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-11-25 | Initial release with full MCP protocol support |

---

## Upgrade Guide

### From Pre-release to 1.0.0

If you were using a development version:

1. Pull the latest code
2. Rebuild Docker image: `docker-compose build --no-cache`
3. Update VS Code settings to use new configuration format
4. Restart the server and VS Code

### Configuration Changes

The server now uses `server_mcp_http.py` as the default for Docker deployments, which provides full MCP protocol compatibility.

---

## Contributors

- Initial development and documentation

---

## License

MIT License - See LICENSE file for details
