# Docker & SSE Integration Guide

This guide explains how to run the GraphQL MCP server in Docker and connect to it using Server-Sent Events (SSE) transport.

## Quick Start with Docker

### 1. Build and Run

```bash
# Set your GraphQL endpoint
export GRAPHQL_ENDPOINT="https://rickandmortyapi.com/graphql"

# Build and start the container
docker-compose up -d

# Check if it's running
docker-compose ps
```

### 2. Test the Server

```bash
# Health check
curl http://localhost:8000/health

# List available tools
curl http://localhost:8000/tools

# Execute a query
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "graphql_query", "arguments": {"query": "{ __typename }"}}'
```

---

## Docker Configuration

### Using Docker Compose (Recommended)

Create a `.env` file with your configuration:

```env
GRAPHQL_ENDPOINT=https://your-api.com/graphql
GRAPHQL_AUTH_TOKEN=your_optional_token
GRAPHQL_HEADERS={"X-Custom-Header": "value"}
MCP_PORT=8000
```

Then run:

```bash
docker-compose up -d
```

### Using Docker Directly

```bash
# Build the image
docker build -t graphql-mcp-server .

# Run the container
docker run -d \
  --name graphql-mcp \
  -p 8000:8000 \
  -e GRAPHQL_ENDPOINT="https://rickandmortyapi.com/graphql" \
  -e GRAPHQL_AUTH_TOKEN="" \
  graphql-mcp-server

# Check logs
docker logs graphql-mcp

# Stop the container
docker stop graphql-mcp
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GRAPHQL_ENDPOINT` | ✅ Yes | Your GraphQL API URL |
| `GRAPHQL_AUTH_TOKEN` | No | Bearer token for authentication |
| `GRAPHQL_HEADERS` | No | Custom headers as JSON string |
| `MCP_HOST` | No | Server host (default: `0.0.0.0`) |
| `MCP_PORT` | No | Server port (default: `8000`) |

---

## SSE (Server-Sent Events) Transport

The HTTP server supports SSE for real-time streaming connections.

### SSE Endpoint

```
GET http://localhost:8000/sse
```

### Connecting to SSE with JavaScript

```javascript
// Connect to the SSE endpoint
const eventSource = new EventSource('http://localhost:8000/sse');

// Handle connection
eventSource.addEventListener('connected', (event) => {
  console.log('Connected:', JSON.parse(event.data));
});

// Handle ready state
eventSource.addEventListener('ready', (event) => {
  console.log('Server ready:', JSON.parse(event.data));
});

// Handle ping (keepalive)
eventSource.addEventListener('ping', (event) => {
  console.log('Ping:', JSON.parse(event.data));
});

// Handle errors
eventSource.addEventListener('error', (event) => {
  console.error('SSE Error:', event);
});

// Close connection when done
// eventSource.close();
```

### Connecting to SSE with Python

```python
import sseclient
import requests

def connect_sse():
    url = "http://localhost:8000/sse"
    response = requests.get(url, stream=True)
    client = sseclient.SSEClient(response)
    
    for event in client.events():
        print(f"Event: {event.event}")
        print(f"Data: {event.data}")
        print("---")

# Install: pip install sseclient-py requests
connect_sse()
```

### Connecting to SSE with curl

```bash
# Stream SSE events
curl -N http://localhost:8000/sse

# Output:
# event: connected
# data: {"status": "connected", "server": "graphql-mcp-server"}
#
# event: ready  
# data: {"status": "ready"}
#
# event: ping
# data: {"timestamp": "..."}
```

---

## HTTP API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/tools` | List available MCP tools |
| POST | `/execute` | Execute an MCP tool |
| GET | `/sse` | Server-Sent Events stream |

### Execute Tool Request

```bash
POST /execute
Content-Type: application/json

{
  "tool": "graphql_query",
  "arguments": {
    "query": "{ users { id name } }",
    "variables": {}
  }
}
```

### Execute Tool Response

```json
{
  "tool": "graphql_query",
  "result": [
    {
      "type": "text",
      "text": "{\"query_used\": \"...\", \"variables\": null, \"result\": {...}}"
    }
  ]
}
```

---

## Integration Examples

### Example 1: Node.js Client

```javascript
const fetch = require('node-fetch');

async function executeGraphQL(query, variables = {}) {
  const response = await fetch('http://localhost:8000/execute', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tool: 'graphql_query',
      arguments: { query, variables }
    })
  });
  
  const data = await response.json();
  return JSON.parse(data.result[0].text);
}

// Usage
const result = await executeGraphQL('{ characters { results { name } } }');
console.log(result);
```

### Example 2: Python Client

```python
import requests
import json

def execute_graphql(query: str, variables: dict = None):
    response = requests.post(
        'http://localhost:8000/execute',
        json={
            'tool': 'graphql_query',
            'arguments': {
                'query': query,
                'variables': variables or {}
            }
        }
    )
    result = response.json()
    return json.loads(result['result'][0]['text'])

# Usage
result = execute_graphql('{ characters { results { name } } }')
print(result['query_used'])
print(result['result'])
```

### Example 3: Shell Script

```bash
#!/bin/bash

ENDPOINT="http://localhost:8000/execute"

# Function to execute GraphQL query
graphql_query() {
    local query="$1"
    curl -s -X POST "$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"tool\": \"graphql_query\", \"arguments\": {\"query\": \"$query\"}}" \
        | jq -r '.result[0].text' | jq .
}

# Get schema
get_schema() {
    curl -s -X POST "$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d '{"tool": "graphql_get_schema", "arguments": {}}' \
        | jq -r '.result[0].text' | jq -r '.result.schema'
}

# Usage
graphql_query "{ characters(page: 1) { results { id name } } }"
```

---

## Claude Desktop with Docker SSE

You can configure Claude Desktop to use the Docker-hosted SSE server.

### Option 1: Direct HTTP Integration

While Claude Desktop primarily uses stdio transport, you can create a bridge script:

```python
#!/usr/bin/env python3
"""Bridge script to connect Claude Desktop to HTTP/SSE server"""

import sys
import json
import requests

SERVER_URL = "http://localhost:8000"

def handle_request(request):
    """Forward MCP requests to HTTP server"""
    if request.get("method") == "tools/list":
        response = requests.get(f"{SERVER_URL}/tools")
        tools = response.json()["tools"]
        return {"tools": tools}
    
    elif request.get("method") == "tools/call":
        tool_name = request["params"]["name"]
        arguments = request["params"].get("arguments", {})
        
        response = requests.post(
            f"{SERVER_URL}/execute",
            json={"tool": tool_name, "arguments": arguments}
        )
        result = response.json()
        return {"content": result["result"]}
    
    return {"error": "Unknown method"}

def main():
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response))
            sys.stdout.flush()
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
```

### Option 2: Use the stdio server directly

For Claude Desktop, it's simpler to use the stdio transport:

```json
{
  "mcpServers": {
    "graphql": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "GRAPHQL_ENDPOINT=https://rickandmortyapi.com/graphql",
        "graphql-mcp-server",
        "python", "server.py"
      ]
    }
  }
}
```

---

## Production Deployment

### Docker Compose with Traefik

```yaml
services:
  graphql-mcp:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.graphql-mcp.rule=Host(`graphql-mcp.yourdomain.com`)"
      - "traefik.http.routers.graphql-mcp.tls=true"
      - "traefik.http.routers.graphql-mcp.tls.certresolver=letsencrypt"
    environment:
      - GRAPHQL_ENDPOINT=${GRAPHQL_ENDPOINT}
      - GRAPHQL_AUTH_TOKEN=${GRAPHQL_AUTH_TOKEN}
    networks:
      - traefik

networks:
  traefik:
    external: true
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: graphql-mcp-server
spec:
  replicas: 2
  selector:
    matchLabels:
      app: graphql-mcp
  template:
    metadata:
      labels:
        app: graphql-mcp
    spec:
      containers:
      - name: graphql-mcp
        image: graphql-mcp-server:latest
        ports:
        - containerPort: 8000
        env:
        - name: GRAPHQL_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: graphql-secrets
              key: endpoint
        - name: GRAPHQL_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: graphql-secrets
              key: auth-token
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: graphql-mcp-service
spec:
  selector:
    app: graphql-mcp
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

---

## Monitoring & Logs

### View Container Logs

```bash
# Follow logs
docker-compose logs -f graphql-mcp

# Last 100 lines
docker-compose logs --tail=100 graphql-mcp
```

### Health Monitoring

```bash
# Check health endpoint
watch -n 5 'curl -s http://localhost:8000/health | jq .'

# Docker health status
docker inspect --format='{{.State.Health.Status}}' graphql-mcp-server
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs graphql-mcp

# Verify environment variables
docker-compose config

# Rebuild without cache
docker-compose build --no-cache
```

### Connection refused

```bash
# Check if container is running
docker-compose ps

# Check port mapping
docker port graphql-mcp-server

# Test from inside container
docker exec graphql-mcp-server curl http://localhost:8000/health
```

### SSE connection drops

- Ensure your reverse proxy supports SSE (long-lived connections)
- Increase timeout settings in nginx/traefik
- Check for firewall rules blocking long connections

### Network issues

```bash
# Test DNS resolution inside container
docker exec graphql-mcp-server nslookup your-graphql-api.com

# Test connectivity
docker exec graphql-mcp-server curl -I https://your-graphql-api.com/graphql
```
