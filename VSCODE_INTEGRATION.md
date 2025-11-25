# VS Code MCP Integration Guide

This guide explains how to connect VS Code to the GraphQL MCP server over the network using the Streamable HTTP transport.

## Prerequisites

1. **GraphQL MCP Server** running (locally or remotely)
2. **VS Code** with GitHub Copilot or an MCP-compatible extension
3. Network access to the MCP server

## Starting the Server

### Option 1: Docker (Recommended)

```bash
# Set your GraphQL endpoint
export GRAPHQL_ENDPOINT="https://rickandmortyapi.com/graphql"

# Start with Docker Compose
docker-compose up -d

# Server available at http://localhost:8000
```

### Option 2: Local Python

```bash
cd /github/Graphql_MCP
source venv/bin/activate
python server_mcp_http.py  # Use the MCP-compatible server

# Server available at http://localhost:8000
```

### Option 3: Remote Server

If running on a remote machine, ensure the port is accessible:

```bash
# On remote server
export MCP_HOST=0.0.0.0
export MCP_PORT=8000
export GRAPHQL_ENDPOINT="https://your-api.com/graphql"
python server_mcp_http.py

# Or with Docker
docker run -d -p 8000:8000 \
  -e GRAPHQL_ENDPOINT="https://your-api.com/graphql" \
  graphql-mcp-server
```

---

## VS Code Configuration

### Method 1: User Settings (Recommended)

1. Open VS Code Settings (`Cmd/Ctrl + ,`)
2. Click the "Open Settings (JSON)" icon in the top right
3. Add the MCP server configuration:

```json
{
  "mcp": {
    "servers": {
      "graphql": {
        "type": "http",
        "url": "http://localhost:8000"
      }
    }
  }
}
```

For a remote server:

```json
{
  "mcp": {
    "servers": {
      "graphql": {
        "type": "http",
        "url": "http://192.168.1.100:8000"
      }
    }
  }
}
```

### Method 2: Workspace Configuration

Create `.vscode/settings.json` in your project:

```json
{
  "mcp": {
    "servers": {
      "graphql-mcp": {
        "type": "http",
        "url": "http://localhost:8000"
      }
    }
  }
}
```

### Method 3: mcp.json Configuration File

Create `mcp.json` in your workspace root:

```json
{
  "servers": {
    "graphql": {
      "type": "http",
      "url": "http://localhost:8000"
    }
  }
}
```

---

## MCP Protocol Endpoints

The server implements the MCP Streamable HTTP transport:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | POST | Main MCP JSON-RPC endpoint |
| `/` | GET | SSE endpoint for server-to-client streaming |
| `/sse` | GET | Alternative SSE endpoint |
| `/messages` | POST | Messages for SSE sessions |

### Convenience Endpoints (for testing)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/tools` | GET | List available tools |
| `/execute` | POST | Execute a tool directly |

---

## Testing the MCP Protocol

### Test Initialize

```bash
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test", "version": "1.0"}
    }
  }'
```

### Test List Tools

```bash
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}'
```

### Test Call Tool

```bash
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "graphql_query",
      "arguments": {"query": "{ characters { results { name } } }"}
    }
  }'
```

---

## SSE Connection for Real-time Updates

For extensions that support SSE:

```
GET http://localhost:8000/sse
```

The SSE endpoint sends these events:
- `endpoint` - URL to POST messages to
- `message` - Response messages from the server
- `ping` - Keepalive (every 30 seconds)

---

## Network Configuration

### Local Network Access

If VS Code and the server are on the same network:

1. Find server IP: `hostname -I` or `ipconfig`
2. Use that IP in VS Code: `http://192.168.1.100:8000`

### Remote Access via SSH Tunnel

For secure remote access:

```bash
# Create SSH tunnel from your local machine
ssh -L 8000:localhost:8000 user@remote-server

# Now access via localhost in VS Code
# URL: http://localhost:8000
```

### Docker with Custom Network

```yaml
# docker-compose.yml
services:
  graphql-mcp:
    build: .
    ports:
      - "0.0.0.0:8000:8000"  # Bind to all interfaces
    environment:
      - GRAPHQL_ENDPOINT=${GRAPHQL_ENDPOINT}
```

### Firewall Configuration

If you can't connect, check firewall:

```bash
# Linux (ufw)
sudo ufw allow 8000/tcp

# Linux (firewalld)
sudo firewall-cmd --add-port=8000/tcp --permanent
sudo firewall-cmd --reload

# Windows (PowerShell as Admin)
New-NetFirewallRule -DisplayName "MCP Server" -Direction Inbound -Port 8000 -Protocol TCP -Action Allow
```

---

## Testing the Connection

### From VS Code Terminal

```bash
# Test health endpoint
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","server":"graphql-mcp-server"}

# List tools
curl http://localhost:8000/tools

# Test a query
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "graphql_query", "arguments": {"query": "{ __typename }"}}'
```

### Using VS Code REST Client Extension

Create a file `test.http`:

```http
### Health Check
GET http://localhost:8000/health

### List Tools
GET http://localhost:8000/tools

### Execute Query
POST http://localhost:8000/execute
Content-Type: application/json

{
  "tool": "graphql_query",
  "arguments": {
    "query": "{ characters { results { name } } }"
  }
}

### Get Schema
POST http://localhost:8000/execute
Content-Type: application/json

{
  "tool": "graphql_get_schema",
  "arguments": {}
}
```

---

## Available Tools

Once connected, these tools are available:

### 1. `graphql_introspection`
Discover the complete GraphQL schema.

### 2. `graphql_get_schema`
Get human-readable schema in SDL format.

### 3. `graphql_query`
Execute GraphQL queries with optional variables.

### 4. `graphql_mutation`
Execute GraphQL mutations to modify data.

---

## Example Prompts in VS Code

Once configured, try these prompts in Copilot Chat:

- *"What queries are available in the GraphQL API?"*
- *"Get the schema for the GraphQL endpoint"*
- *"Query all characters from the API"*
- *"Find users with email containing 'example.com'"*

---

## Troubleshooting

### "Connection refused"

1. Check if server is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. Verify port binding:
   ```bash
   # Check what's listening on port 8000
   lsof -i :8000
   # or
   netstat -tlnp | grep 8000
   ```

3. If using Docker, check container status:
   ```bash
   docker ps
   docker logs graphql-mcp-server
   ```

### "CORS errors" (for web-based extensions)

Add CORS headers to the server. Edit `server_http.py` to add middleware:

```python
from starlette.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### "Timeout errors"

1. Check network latency to server
2. Increase timeout in VS Code settings
3. Verify the GraphQL endpoint is responding

### "Tools not showing"

1. Restart VS Code after configuration changes
2. Check the MCP extension logs (View → Output → select MCP)
3. Verify the `/tools` endpoint returns data

---

## Security Considerations

### For Production Use

1. **Use HTTPS**: Put the server behind a reverse proxy with TLS
2. **Authentication**: Add API key validation
3. **Network Isolation**: Use VPN or SSH tunnels for remote access
4. **Rate Limiting**: Implement request throttling

### Example: Nginx Reverse Proxy with HTTPS

```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;  # For SSE
    }
}
```

---

## Quick Reference

| Task | Command/URL |
|------|-------------|
| Start server (Docker) | `docker-compose up -d` |
| Start server (Python) | `python server_http.py` |
| Health check | `GET http://localhost:8000/health` |
| List tools | `GET http://localhost:8000/tools` |
| Execute tool | `POST http://localhost:8000/execute` |
| SSE stream | `GET http://localhost:8000/sse` |
| View logs | `docker logs graphql-mcp-server` |
| Stop server | `docker-compose down` |
