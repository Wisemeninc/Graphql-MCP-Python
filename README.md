# GraphQL MCP Server

A Model Context Protocol (MCP) server that enables LLMs to interact with GraphQL APIs. This server provides tools for introspection, querying, and mutating data through GraphQL endpoints.

## Features

- **GraphQL Introspection**: Discover schema, types, queries, mutations, and fields
- **Query Execution**: Execute GraphQL queries with variables
- **Mutation Support**: Perform data modifications through GraphQL mutations
- **Schema Retrieval**: Get human-readable schema in SDL format
- **Query Transparency**: Every response includes the query/mutation used and the result
- **Multiple Transports**: Supports both stdio and HTTP/SSE transports
- **Docker Support**: Run in containers with Docker and Docker Compose
- **Kubernetes Ready**: Full K8s manifests with HPA, Network Policies, and more
- **GitHub OAuth**: Optional authentication with user/org-based access control

## Quick Start with Docker

```bash
# Clone and enter directory
cd /github/Graphql_MCP

# Set your GraphQL endpoint
export GRAPHQL_ENDPOINT="https://rickandmortyapi.com/graphql"

# Build and run
docker-compose up -d

# Test it
curl http://localhost:8000/health
curl http://localhost:8000/tools
```

See [DOCKER_SSE_GUIDE.md](docs/DOCKER_SSE_GUIDE.md) for full Docker and SSE documentation.

See [KUBERNETES_GUIDE.md](docs/KUBERNETES_GUIDE.md) for Kubernetes deployment instructions.

See [GITHUB_OAUTH.md](docs/GITHUB_OAUTH.md) for GitHub OAuth authentication setup.

## Installation (Without Docker)

1. Clone the repository:
```bash
cd /github/Graphql_MCP
```

2. Install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your GraphQL endpoint and credentials
```

## Configuration

Create a `.env` file with the following variables:

```env
# Required: Your GraphQL endpoint
GRAPHQL_ENDPOINT=https://api.example.com/graphql

# Optional: Authentication token
GRAPHQL_AUTH_TOKEN=your_bearer_token_here

# Optional: Custom headers as JSON
GRAPHQL_HEADERS={"X-Custom-Header": "value"}

# Optional: HTTP server configuration (for HTTP/SSE transport)
MCP_HOST=0.0.0.0
MCP_PORT=8000
```

## Usage

### Option 1: Claude Desktop Integration (Recommended)

The easiest way to use this MCP server is with Claude Desktop. Add the following configuration to your Claude Desktop settings:

#### Step 1: Locate your Claude Desktop config file

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

#### Step 2: Add the MCP server configuration

Edit the config file and add the GraphQL MCP server:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "/path/to/Graphql_MCP/venv/bin/python",
      "args": ["/path/to/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://your-graphql-api.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "your_optional_bearer_token"
      }
    }
  }
}
```

#### Step 3: Example configurations

**Public API (Rick and Morty):**
```json
{
  "mcpServers": {
    "graphql": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://rickandmortyapi.com/graphql"
      }
    }
  }
}
```

**GitHub GraphQL API:**
```json
{
  "mcpServers": {
    "github-graphql": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.github.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "ghp_your_github_token"
      }
    }
  }
}
```

**Hasura/Custom API with headers:**
```json
{
  "mcpServers": {
    "hasura": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://your-hasura-instance.hasura.app/v1/graphql",
        "GRAPHQL_HEADERS": "{\"x-hasura-admin-secret\": \"your-secret\"}"
      }
    }
  }
}
```

#### Step 4: Restart Claude Desktop

After saving the config file, restart Claude Desktop completely to load the new MCP server.

#### Step 5: Verify the connection

In Claude Desktop, you should now see the GraphQL tools available. Try asking Claude:
- "What GraphQL queries are available?"
- "Show me the GraphQL schema"
- "Query all characters from the API"

### Option 2: Stdio Transport (for other MCP clients)

Run the server with stdio transport:

```bash
python server.py
```

This mode is suitable for direct integration with MCP clients that communicate via stdin/stdout.

### Option 3: HTTP/SSE Transport (for web-based clients)

Run the server with HTTP and Server-Sent Events:

```bash
python server_http.py
```

The server will start on `http://0.0.0.0:8000` (configurable via environment variables).

#### HTTP Endpoints

- `GET /health` - Health check
- `GET /tools` - List available tools
- `POST /execute` - Execute a tool
- `GET /sse` - Server-Sent Events stream

#### Example HTTP Request

```bash
# List available tools
curl http://localhost:8000/tools

# Execute introspection
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "graphql_introspection", "arguments": {}}'

# Execute a query
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "{ users { id name email } }"
    }
  }'

# Execute a query with variables
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
      "variables": {"id": "123"}
    }
  }'
```

## Available Tools

### 1. graphql_introspection

Performs GraphQL introspection to discover the complete schema.

**Parameters:** None

**Returns:**
```json
{
  "query_used": "GraphQL Introspection Query",
  "result": { /* Full introspection result */ }
}
```

### 2. graphql_get_schema

Gets the human-readable GraphQL schema in SDL format.

**Parameters:** None

**Returns:**
```json
{
  "query_used": "GraphQL Introspection Query (converted to SDL)",
  "result": {
    "schema": "type Query { ... }"
  }
}
```

### 3. graphql_query

Executes a GraphQL query.

**Parameters:**
- `query` (string, required): The GraphQL query to execute
- `variables` (object, optional): Variables for the query

**Returns:**
```json
{
  "query_used": "{ users { id name } }",
  "variables": null,
  "result": { /* Query result */ }
}
```

### 4. graphql_mutation

Executes a GraphQL mutation.

**Parameters:**
- `mutation` (string, required): The GraphQL mutation to execute
- `variables` (object, optional): Variables for the mutation

**Returns:**
```json
{
  "mutation_used": "mutation { createUser(input: {...}) { id } }",
  "variables": {...},
  "result": { /* Mutation result */ }
}
```

## Example Workflows

### Discovering the Schema

1. Use `graphql_introspection` to get the full schema structure
2. Or use `graphql_get_schema` for a more readable SDL format

### Querying Data

1. First, introspect to understand available queries
2. Execute queries using `graphql_query` with appropriate fields
3. Use variables for dynamic queries

### Mutating Data

1. Discover available mutations via introspection
2. Execute mutations using `graphql_mutation`
3. Always review the returned query/mutation for debugging

## Security Considerations

- Store sensitive tokens in `.env` file (never commit to version control)
- Use HTTPS for GraphQL endpoints in production
- Configure appropriate authentication headers
- Review and sanitize queries before execution in production environments

## Troubleshooting

### Connection Errors

- Verify `GRAPHQL_ENDPOINT` is correct and accessible
- Check authentication token if required
- Ensure network connectivity to the GraphQL server

### Query Errors

- Review the `query_used` field in responses for debugging
- Validate query syntax against the schema
- Check variable types match schema requirements

## Development

### Running Tests

```bash
# Add your test commands here
pytest
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License

## Scripts and Utilities

Helper scripts for setup, testing, and examples are in the [scripts/](scripts/) directory:

- [setup.sh](scripts/setup.sh) - Automated environment setup
- [run.sh](scripts/run.sh) - Convenience server runner
- [test_setup.py](scripts/test_setup.py) - Setup verification tool
- [example_client.py](scripts/example_client.py) - Usage examples

See [scripts/README.md](scripts/README.md) for detailed usage instructions.

## Documentation

For comprehensive documentation, see the [docs/](docs/) directory:

- [Quick Start Guide](docs/QUICKSTART.md)
- [API Reference](docs/API_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Changelog](docs/CHANGELOG.md)
- [Integration Guides](docs/README.md) - Claude Desktop, VS Code, Docker, Kubernetes

## Support

For issues and questions, please open an issue on GitHub.
