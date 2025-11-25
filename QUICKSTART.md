# GraphQL MCP Server - Quick Start Guide

## Overview

This GraphQL MCP (Model Context Protocol) server allows LLMs to interact with GraphQL APIs. It provides introspection, query execution, and mutation capabilities with full transparency—every response includes both the query used and the result.

## Installation

### 1. Quick Setup (Automated)

```bash
./setup.sh
```

This script will:
- Create a virtual environment
- Install all dependencies
- Create a `.env` file from `.env.example`

### 2. Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### 3. Verify Setup

```bash
python test_setup.py
```

## Configuration

Edit `.env` file:

```env
# Required: Your GraphQL endpoint
GRAPHQL_ENDPOINT=https://api.example.com/graphql

# Optional: Bearer token for authentication
GRAPHQL_AUTH_TOKEN=your_token_here

# Optional: Custom headers (JSON format)
GRAPHQL_HEADERS={"X-API-Key": "your-key"}

# Optional: HTTP server settings
MCP_HOST=0.0.0.0
MCP_PORT=8000
```

## Running the Server

### Option A: Claude Desktop Integration (Recommended)

The best way to use this MCP server is with Claude Desktop.

#### 1. Find your Claude Desktop config file

| Platform | Config File Location |
|----------|---------------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

#### 2. Add the GraphQL MCP server

Open the config file and add:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "/path/to/Graphql_MCP/venv/bin/python",
      "args": ["/path/to/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://your-api.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "optional_token"
      }
    }
  }
}
```

> **Important**: Replace `/path/to/Graphql_MCP` with your actual installation path.

#### 3. Example: Rick and Morty API (no auth required)

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

#### 4. Restart Claude Desktop

Fully quit and restart Claude Desktop to load the MCP server.

#### 5. Test it!

Ask Claude:
- *"What's the GraphQL schema?"*
- *"Query all characters"*
- *"Get the first 5 episodes"*

---

### Option B: Stdio Transport (for other MCP clients)

Best for direct integration with Claude Desktop, Continue, or other local MCP clients.

```bash
python server.py
```

### Option C: HTTP/SSE Transport (for web clients)

Best for web-based integrations or when you need HTTP endpoints.

```bash
python server_http.py
```

Server will be available at `http://localhost:8000`

## Available Tools

### 1. graphql_introspection

Discovers the complete GraphQL schema.

**Example Response:**
```json
{
  "query_used": "GraphQL Introspection Query",
  "result": {
    "__schema": {
      "types": [...],
      "queryType": {...}
    }
  }
}
```

### 2. graphql_get_schema

Returns human-readable schema in SDL format.

**Example Response:**
```json
{
  "query_used": "GraphQL Introspection Query (converted to SDL)",
  "result": {
    "schema": "type Query {\n  users: [User!]!\n}\n\ntype User {\n  id: ID!\n  name: String!\n}"
  }
}
```

### 3. graphql_query

Executes GraphQL queries.

**Input:**
```json
{
  "query": "{ users { id name email } }",
  "variables": {}
}
```

**Example Response:**
```json
{
  "query_used": "{ users { id name email } }",
  "variables": null,
  "result": {
    "users": [
      {"id": "1", "name": "Alice", "email": "alice@example.com"},
      {"id": "2", "name": "Bob", "email": "bob@example.com"}
    ]
  }
}
```

### 4. graphql_mutation

Executes GraphQL mutations.

**Input:**
```json
{
  "mutation": "mutation CreateUser($name: String!) { createUser(name: $name) { id name } }",
  "variables": {"name": "Charlie"}
}
```

**Example Response:**
```json
{
  "mutation_used": "mutation CreateUser($name: String!) { createUser(name: $name) { id name } }",
  "variables": {"name": "Charlie"},
  "result": {
    "createUser": {
      "id": "3",
      "name": "Charlie"
    }
  }
}
```

## HTTP/SSE Usage Examples

### List Available Tools

```bash
curl http://localhost:8000/tools
```

### Execute Introspection

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "graphql_introspection", "arguments": {}}'
```

### Execute a Query

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "{ users { id name } }"
    }
  }'
```

### Execute Query with Variables

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
      "variables": {"id": "123"}
    }
  }'
```

### Execute a Mutation

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_mutation",
    "arguments": {
      "mutation": "mutation { createUser(name: \"John\") { id name } }"
    }
  }'
```

## Integration with Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "python",
      "args": ["/path/to/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.example.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "your_token_here"
      }
    }
  }
}
```

## Common Use Cases

### 1. Explore an Unknown API

```
LLM: Use graphql_introspection to discover available queries and types
→ Use graphql_get_schema for readable schema
→ Execute specific queries based on schema
```

### 2. Fetch Data

```
LLM: Use graphql_query with appropriate fields
→ Variables for dynamic queries
→ Review query_used in response for debugging
```

### 3. Modify Data

```
LLM: Use graphql_introspection to find mutations
→ Execute graphql_mutation with required variables
→ Verify result in response
```

## Troubleshooting

### "GRAPHQL_ENDPOINT environment variable is required"

Make sure `.env` file exists and contains `GRAPHQL_ENDPOINT=your_url_here`

### Authentication Errors

- Verify `GRAPHQL_AUTH_TOKEN` is correct
- Check if the API requires specific headers in `GRAPHQL_HEADERS`

### Query Syntax Errors

- Review the `query_used` field in error responses
- Validate against schema using introspection
- Check variable types match schema requirements

### Connection Issues

- Verify endpoint URL is accessible
- Check network connectivity
- Review firewall settings

## Advanced Configuration

### Custom Headers

```env
GRAPHQL_HEADERS={"X-API-Key": "key123", "X-Custom-Header": "value"}
```

### Multiple Environments

Create environment-specific files:
- `.env.development`
- `.env.production`

Load specific environment:
```bash
cp .env.production .env
python server_http.py
```

## Performance Tips

1. **Cache Introspection Results**: The schema doesn't change often
2. **Use Variables**: More efficient than inline values
3. **Request Only Needed Fields**: Reduce payload size
4. **Batch Related Queries**: Use fragments and aliases

## Security Best Practices

1. ✓ Never commit `.env` file
2. ✓ Use HTTPS endpoints in production
3. ✓ Rotate authentication tokens regularly
4. ✓ Limit exposed fields in queries
5. ✓ Validate and sanitize inputs
6. ✓ Monitor API usage and rate limits

## Support

For issues or questions:
1. Check the logs for detailed error messages
2. Verify setup with `python test_setup.py`
3. Review GraphQL API documentation
4. Open an issue on GitHub

## Examples

See `example_client.py` for more usage examples and query patterns.
