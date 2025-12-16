# Claude Desktop Integration Guide

This guide explains how to integrate the GraphQL MCP server with Claude Desktop, allowing Claude to directly interact with your GraphQL APIs.

## Prerequisites

1. **Claude Desktop** installed on your computer
2. **Python 3.10+** installed
3. **GraphQL MCP Server** set up (run `./scripts/setup.sh` first)

## Quick Setup

### Step 1: Find Your Config File

The Claude Desktop configuration file location depends on your operating system:

| Platform | Configuration File Path |
|----------|------------------------|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

### Step 2: Edit the Configuration

Open the config file in your favorite text editor. If the file doesn't exist, create it.

Add the GraphQL MCP server to the `mcpServers` section:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "/absolute/path/to/Graphql_MCP/venv/bin/python",
      "args": ["/absolute/path/to/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://your-graphql-endpoint.com/graphql"
      }
    }
  }
}
```

> ⚠️ **Important**: Use **absolute paths** for both the Python executable and the server script.

### Step 3: Restart Claude Desktop

Completely quit Claude Desktop (not just close the window) and reopen it to load the new configuration.

### Step 4: Verify Connection

In Claude Desktop, the GraphQL tools should now be available. Try asking:

- "What GraphQL tools do you have available?"
- "Show me the GraphQL schema"
- "Query all users from the API"

---

## Configuration Examples

### Example 1: Public API (No Authentication)

For public APIs like the Rick and Morty API:

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

**Sample queries to try:**
- "Get all characters from Rick and Morty"
- "Find episode details for season 1"
- "Search for characters named Rick"

---

### Example 2: GitHub GraphQL API

For GitHub's GraphQL API (requires a personal access token):

```json
{
  "mcpServers": {
    "github-graphql": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.github.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

**To get a GitHub token:**
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate a new token with required scopes
3. Copy the token into the config

**Sample queries to try:**
- "Get my GitHub repositories"
- "Show my recent pull requests"
- "Find issues in repository owner/repo"

---

### Example 3: Hasura GraphQL Engine

For Hasura with admin secret authentication:

```json
{
  "mcpServers": {
    "hasura": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://your-project.hasura.app/v1/graphql",
        "GRAPHQL_HEADERS": "{\"x-hasura-admin-secret\": \"your-admin-secret\"}"
      }
    }
  }
}
```

---

### Example 4: Apollo Studio / Self-Hosted API

For APIs requiring custom headers:

```json
{
  "mcpServers": {
    "my-api": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.mycompany.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "your_jwt_token",
        "GRAPHQL_HEADERS": "{\"X-API-Key\": \"api-key\", \"X-Client-ID\": \"claude-desktop\"}"
      }
    }
  }
}
```

---

### Example 5: Multiple GraphQL APIs

You can configure multiple GraphQL endpoints:

```json
{
  "mcpServers": {
    "rickandmorty": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://rickandmortyapi.com/graphql"
      }
    },
    "github": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.github.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxx"
      }
    },
    "my-backend": {
      "command": "/github/Graphql_MCP/venv/bin/python",
      "args": ["/github/Graphql_MCP/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.myapp.com/graphql",
        "GRAPHQL_AUTH_TOKEN": "my-api-token"
      }
    }
  }
}
```

---

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `GRAPHQL_ENDPOINT` | ✅ Yes | The GraphQL API URL | `https://api.example.com/graphql` |
| `GRAPHQL_AUTH_TOKEN` | No | Bearer token for Authorization header | `your_token_here` |
| `GRAPHQL_HEADERS` | No | Custom headers as JSON string | `{"X-API-Key": "key123"}` |

---

## Available Tools in Claude

Once configured, Claude will have access to these tools:

### 1. `graphql_introspection`
Discovers the complete API schema including all types, queries, and mutations.

**Ask Claude:** "What queries and mutations are available in this GraphQL API?"

### 2. `graphql_get_schema`
Gets a human-readable version of the schema in SDL format.

**Ask Claude:** "Show me the GraphQL schema in a readable format"

### 3. `graphql_query`
Executes GraphQL queries to fetch data.

**Ask Claude:** "Query all users with their email addresses"

### 4. `graphql_mutation`
Executes GraphQL mutations to create, update, or delete data.

**Ask Claude:** "Create a new user named John with email john@example.com"

---

## Troubleshooting

### "Tools not appearing in Claude"

1. **Check the config file syntax**: Ensure valid JSON (no trailing commas)
2. **Verify paths are absolute**: Relative paths won't work
3. **Restart Claude Desktop completely**: Quit the app, don't just close the window
4. **Check Python path**: Run `which python` in the venv to get the correct path

### "Connection errors"

1. **Test the endpoint**: Try accessing the GraphQL endpoint in a browser
2. **Check authentication**: Verify your token/headers are correct
3. **Network issues**: Ensure no firewall/VPN blocking the connection

### "Permission denied"

1. **Make scripts executable**: `chmod +x server.py`
2. **Check file permissions**: Ensure Claude can read the files
3. **Verify venv activation**: The Python path should point to `venv/bin/python`

### "Module not found errors"

1. **Install dependencies**: Run `pip install -r requirements.txt` in the venv
2. **Use correct Python**: Point to the venv Python, not system Python
3. **Recreate venv if needed**: `rm -rf venv && ./setup.sh`

### Viewing Logs

To see what's happening:

```bash
# Watch the Claude Desktop logs (macOS)
tail -f ~/Library/Logs/Claude/mcp*.log

# Or run the server manually to see output
cd /path/to/Graphql_MCP
source venv/bin/activate
python server.py
```

---

## Tips for Best Results

### 1. Start with Schema Discovery
Always begin by asking Claude to explore the schema:
> "First, show me the GraphQL schema so I understand what data is available"

### 2. Be Specific with Queries
Instead of "get all data", be specific:
> "Query the first 10 users with their id, name, and email fields"

### 3. Use Variables for Dynamic Queries
Ask Claude to use variables:
> "Get the user with ID 123, using a GraphQL variable"

### 4. Review the Query Used
Each response includes the query that was executed:
> "Show me the exact GraphQL query you used"

### 5. Iterate on Complex Queries
Build up complex queries step by step:
1. First query basic fields
2. Add nested relationships
3. Add filtering/pagination

---

## Security Best Practices

1. **Never share your config file** - It contains sensitive tokens
2. **Use environment-specific tokens** - Don't use production tokens for testing
3. **Rotate tokens regularly** - Update your config when tokens change
4. **Limit token permissions** - Use minimal required scopes
5. **Review mutations carefully** - Claude can modify data with mutations

---

## Getting Help

If you encounter issues:

1. Run `python scripts/test_setup.py` to verify your setup
2. Check the [README.md](README.md) for general documentation
3. Review the [API_REFERENCE.md](API_REFERENCE.md) for tool details
4. Open an issue on GitHub with:
   - Your OS and Claude Desktop version
   - Error messages (with sensitive data redacted)
   - Your config structure (without tokens)
