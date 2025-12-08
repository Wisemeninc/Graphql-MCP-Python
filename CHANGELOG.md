# Changelog

All notable changes to the GraphQL MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-12-05

### Added

#### MCP System Prompts
- Added two MCP prompts for LLM guidance:
  - `graphql-assistant` - Comprehensive guide for interacting with the GraphQL API
  - `graphql-explorer` - Focused on schema exploration and discovery
- Prompts provide tool descriptions, best practices, and example queries
- Available via `prompts/list` and `prompts/get` MCP methods

#### API Token Authentication
- Support for static API tokens alongside OAuth 2.1
- `API_TOKENS_ENABLED` environment variable to enable token auth (default: `false`)
- `API_TOKENS` comma-separated list of tokens in format `token:username`
- Bearer token authentication via `Authorization: Bearer <token>` header
- Token-based users logged with "api_token" provider

#### Query and Logon File Logging
- Dedicated file loggers for queries and authentication events
- Query log (`/app/logs/queries.log`) records all tool calls with:
  - Tool name, client IP, authenticated user, and arguments
- Logon log (`/app/logs/logons.log`) records authentication events:
  - Login success/failure, logout, authorization denied
  - User, provider, client IP, and status
- `LOG_DIR` environment variable for log directory (default: `/app/logs`)
- `QUERY_LOG_ENABLED` to enable/disable query logging (default: `true`)
- `LOGON_LOG_ENABLED` to enable/disable logon logging (default: `true`)
- Docker volume mount for persistent logs

#### New Utility Tools
- `ip_info` tool - Get IP geolocation, timezone, and network info using ip-api.com (free, no API key)
- `web_search` tool - Search the web using DuckDuckGo (free, no API key)

### Changed
- Migrated from `duckduckgo-search` to `ddgs` package (upstream rename)
- Authenticated user context now properly passed to MCP tool handlers

### Removed
- Removed `geo_location` tool (required API key)
- Removed `ip_timezone` tool (required API key)

---

## [1.4.0] - 2025-11-28

### Added

#### OAuth 2.1 Authorization Server (RFC 8414, RFC 9728)
- Full OAuth 2.1 Authorization Server implementation for MCP client authentication
- `/.well-known/oauth-authorization-server` - RFC 8414 metadata discovery endpoint
- `/.well-known/oauth-protected-resource` - RFC 9728 protected resource metadata
- `/authorize` - OAuth authorization endpoint (proxies to GitHub/Google/Azure)
- `/token` - Token exchange endpoint with PKCE verification
- Support for MCP clients (VS Code) to authenticate via standard OAuth flow
- Authorization code generation and one-time-use validation
- Proper HTTPS URL generation via X-Forwarded-Proto/Host headers (Traefik support)

#### SSL/TLS Configuration
- `SSL_VERIFY` environment variable to control certificate verification
- Configurable SSL for GraphQL client connections
- Support for self-signed certificates in development environments

### Changed
- OAuth metadata endpoints now respect reverse proxy headers for correct URL generation
- Improved auth_callback to handle both legacy and OAuth AS flows

### Fixed
- Fixed HTTP URLs in OAuth metadata when behind TLS-terminating reverse proxy

---

## [1.3.0] - 2025-11-27

### Added

#### OAuth 2.1 Authentication with PKCE
- Full OAuth 2.1 implementation with PKCE (Proof Key for Code Exchange)
- Support for multiple providers: GitHub, Google, Azure AD
- `oauth21.py` - Complete OAuth 2.1 client implementation
- Token store with automatic cleanup and refresh token rotation
- User/group-based authorization controls
- `OAUTH_ENABLED`, `OAUTH_PROVIDER` environment variables
- `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` for provider credentials
- `OAUTH_ALLOWED_USERS`, `OAUTH_ALLOWED_GROUPS` for access control

#### TLS/HTTPS Support
- Traefik reverse proxy with automatic Let's Encrypt certificates
- Cloudflare DNS validation for wildcard certificates
- Docker Compose configuration for full TLS setup
- Support for multiple domains/subdomains

### Security
- PKCE S256 challenge verification (OAuth 2.1 requirement)
- Refresh token rotation for enhanced security
- Bearer token validation on MCP endpoints

---

## [1.2.0] - 2025-11-25

### Added

#### GitHub OAuth Authentication
- Optional GitHub OAuth authentication for secure access control
- `GITHUB_AUTH_ENABLED` environment variable to enable/disable
- `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` for OAuth app credentials
- `GITHUB_ALLOWED_USERS` - comma-separated list of allowed GitHub usernames
- `GITHUB_ALLOWED_ORGS` - comma-separated list of allowed GitHub organizations
- `AUTH_TOKEN_EXPIRY` - configurable token lifetime (default 24 hours)
- OAuth endpoints:
  - `GET /auth/login` - Initiate OAuth flow
  - `GET /auth/callback` - OAuth callback handler
  - `GET /auth/status` - Check authentication status
  - `POST /auth/logout` - Invalidate session
- Automatic token cleanup for expired sessions
- CSRF protection via state parameter
- Comprehensive `GITHUB_OAUTH.md` documentation

### Security
- Authentication checks on ALL MCP endpoints when enabled:
  - `POST /` - MCP JSON-RPC endpoint
  - `GET /` and `GET /sse` - SSE endpoints
  - `POST /messages` - Session messages
  - `GET /tools` - Tools listing
  - `POST /execute` - Direct tool execution
- Only `/health` and `/auth/*` endpoints remain public
- Organization membership verification for access control
- Secure token generation using `secrets` module
- Token-based session management
- Returns 401 with auth URL on unauthorized requests

---

## [1.1.0] - 2025-11-25

### Added

#### Debug Logging
- Configurable `LOG_LEVEL` environment variable (DEBUG, INFO, WARNING, ERROR)
- Structured log format with timestamps
- Debug logging for GraphQL client initialization
- Debug logging for all tool handlers (introspection, query, mutation, schema)
- MCP message handling logs with client info
- HTTP endpoint logging with client IP tracking
- SSE connection management logging
- Startup banner showing server configuration and available endpoints
- Silenced noisy third-party loggers (httpx, httpcore, aiohttp)

#### Kubernetes Support
- Complete `k8s/` directory with production-ready manifests
- Namespace, ConfigMap, Secret configurations
- Deployment with security best practices (non-root, read-only fs, dropped capabilities)
- Service and Ingress with SSE-optimized nginx annotations
- HorizontalPodAutoscaler for auto-scaling (2-10 replicas)
- PodDisruptionBudget for high availability
- NetworkPolicy for security
- Kustomization for easy deployment
- Cloud-specific configurations for AWS EKS, GKE, and Azure AKS

### Changed
- Uvicorn log level now follows `LOG_LEVEL` setting

---

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
| 1.5.0 | 2025-12-05 | MCP prompts, API tokens, file logging, ip_info/web_search tools |
| 1.4.0 | 2025-11-28 | OAuth 2.1 Authorization Server |
| 1.3.0 | 2025-11-27 | OAuth 2.1 with PKCE, TLS/HTTPS support |
| 1.2.0 | 2025-11-25 | GitHub OAuth authentication |
| 1.1.0 | 2025-11-25 | Debug logging, Kubernetes support |
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
