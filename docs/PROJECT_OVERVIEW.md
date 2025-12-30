# GraphQL MCP Server - Project Overview

## 🎯 Project Description

A complete Model Context Protocol (MCP) server implementation that enables Large Language Models (LLMs) to interact with GraphQL APIs. Built with Python, featuring both stdio and HTTP/SSE transports for maximum flexibility.

**Current Version:** 1.5.0

## ✨ Key Features

### Core GraphQL Tools
- ✅ **GraphQL Introspection**: Automatically discover API schema, types, and operations
- ✅ **Query Execution**: Execute GraphQL queries with full variable support
- ✅ **Mutation Support**: Modify data through GraphQL mutations
- ✅ **Schema Retrieval**: Get human-readable SDL format schemas
- ✅ **Query Transparency**: Every response includes the query used and result

### Utility Tools
- ✅ **Epoch Converter**: Convert Unix timestamps to human-readable date/time
- ✅ **NTP Time**: Get accurate time from NTP servers
- ✅ **IP Info**: Get IP geolocation and timezone (via ip-api.com)
- ✅ **Web Search**: Search the web via DuckDuckGo (no API key needed)

### Infrastructure
- ✅ **Dual Transport**: stdio for local clients, HTTP/SSE for web integration
- ✅ **OAuth 2.1 Authentication**: GitHub OAuth with PKCE support
- ✅ **API Token Auth**: Simple token-based authentication
- ✅ **MCP System Prompts**: Built-in prompts for GraphQL assistance
- ✅ **Query Logging**: Audit logging for queries and authentication
- ✅ **Production Ready**: Rate limiting, structured logging, error handling

## 📁 Project Structure

```
Graphql-MCP-Python/
├── server.py                      # MCP server with stdio transport
├── server_mcp_http_stateful.py    # HTTP/SSE server (stateful, recommended)
├── event_store.py                 # Event storage (in-memory/Redis)
├── oauth21.py                     # OAuth 2.1 implementation
├── version.py                     # Version information
├── requirements.txt               # Python dependencies
├── Dockerfile                     # Docker container definition
├── docker-compose.yml             # Docker Compose configuration
├── .env.example                   # Environment configuration template
├── README.md                      # Main documentation
├── docs/                          # Extended documentation
│   ├── API_REFERENCE.md
│   ├── ARCHITECTURE.md
│   ├── DOCKER_SSE_GUIDE.md
│   ├── GITHUB_OAUTH.md
│   ├── KUBERNETES_GUIDE.md
│   ├── QUICKSTART.md
│   └── VSCODE_INTEGRATION.md
├── k8s/                           # Kubernetes manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   ├── secret.yaml
│   ├── hpa.yaml
│   ├── ingress.yaml
│   └── networkpolicy.yaml
├── scripts/                       # Helper scripts
│   ├── setup.sh
│   ├── run.sh
│   ├── test_setup.py
│   └── example_client.py
└── logs/                          # Log files (queries.log, logons.log)
```

## 🚀 Quick Start

```bash
# 1. Setup
./scripts/setup.sh

# 2. Configure
cp .env.example .env
nano .env  # Add your GRAPHQL_ENDPOINT

# 3. Run
python server_mcp_http_stateful.py    # HTTP/SSE mode
# or
python server.py                       # stdio mode
```

## 🔧 Available Tools

| Tool | Description | Input | Output |
|------|-------------|-------|--------|
| `graphql_introspection` | Discover complete schema | None | Full introspection result |
| `graphql_get_schema` | Get SDL format schema | None | Human-readable schema |
| `graphql_query` | Execute queries | query, variables | Query + Result |
| `graphql_mutation` | Execute mutations | mutation, variables | Mutation + Result |
| `epoch_to_readable` | Convert timestamps | epoch, format, timezone | Formatted date/time |
| `ntp_time` | Get accurate time | server, include_offset | NTP time + offset |
| `ip_info` | Get IP geolocation | ip (optional) | Location, timezone, ISP |
| `web_search` | Search the web | query, max_results | Search results |

## 📦 Dependencies

- `mcp>=1.22.0` - Model Context Protocol SDK
- `gql>=4.0.0` - GraphQL client
- `graphql-core>=3.2.7` - GraphQL implementation
- `aiohttp>=3.13.0` - Async HTTP client
- `starlette>=0.50.0` - Web framework
- `uvicorn>=0.38.0` - ASGI server
- `sse-starlette>=3.0.0` - Server-Sent Events
- `python-dotenv>=1.2.0` - Environment management
- `pydantic>=2.12.0` - Data validation
- `redis>=5.0.0` - Redis client (for distributed sessions)
- `slowapi>=0.1.9` - Rate limiting
- `ddgs>=9.0.0` - DuckDuckGo search

## 🎮 Usage Examples

### Example 1: Introspection
```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "graphql_introspection", "arguments": {}}'
```

### Example 2: Simple Query
```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "{ users { id name email } }"
    }
  }'
```

### Example 3: Query with Variables
```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_query",
    "arguments": {
      "query": "query GetUser($id: ID!) { user(id: $id) { name } }",
      "variables": {"id": "123"}
    }
  }'
```

### Example 4: Mutation
```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "graphql_mutation",
    "arguments": {
      "mutation": "mutation { createUser(name: \"John\") { id } }"
    }
  }'
```

## 🔐 Security

- Environment-based configuration
- Bearer token authentication support
- Custom header injection
- HTTPS endpoint support
- `.env` file excluded from version control

## 🌐 Transport Modes

### Stdio Transport
- **File**: `server.py`
- **Use Case**: Claude Desktop, Continue, local MCP clients
- **Command**: `python server.py` or `./scripts/run.sh stdio`
- **Communication**: stdin/stdout

### HTTP/SSE Transport
- **File**: `server_http.py`
- **Use Case**: Web applications, remote clients, API integration
- **Command**: `python server_http.py` or `./scripts/run.sh http`
- **Endpoints**:
  - `GET /health` - Health check
  - `GET /tools` - List tools
  - `POST /execute` - Execute tool
  - `GET /sse` - Event stream

## 📊 Response Format

All tool executions return:
```json
{
  "query_used": "<the actual GraphQL query>",
  "variables": {<variables if provided>},
  "result": {<GraphQL response data>}
}
```

This transparency allows LLMs to:
- Debug queries easily
- Learn GraphQL patterns
- Understand data relationships
- Optimize future queries

## 🧪 Testing

```bash
# Verify setup
python test_setup.py

# Or use convenience script
./run.sh test
```

## 📚 Documentation

- **README.md** - Overview and installation
- **QUICKSTART.md** - Step-by-step guide
- **API_REFERENCE.md** - Complete API documentation
- **scripts/example_client.py** - Code examples

## 🎯 Use Cases

1. **API Discovery**: Let LLMs explore unknown GraphQL APIs
2. **Data Retrieval**: Query databases through GraphQL layer
3. **Data Modification**: Execute mutations for CRUD operations
4. **Schema Analysis**: Understand API structure and relationships
5. **Automated Testing**: Use LLMs to generate test queries
6. **Documentation**: Generate API documentation from introspection

## 🔄 Integration Examples

### Claude Desktop
```json
{
  "mcpServers": {
    "graphql": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": {
        "GRAPHQL_ENDPOINT": "https://api.example.com/graphql"
      }
    }
  }
}
```

### JavaScript Client
```javascript
const response = await fetch('http://localhost:8000/execute', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    tool: 'graphql_query',
    arguments: {query: '{ users { id name } }'}
  })
});
```

### Python Client
```python
import requests

response = requests.post('http://localhost:8000/execute', json={
    'tool': 'graphql_query',
    'arguments': {
        'query': '{ users { id name } }'
    }
})
```

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Import errors | Run `pip install -r requirements.txt` |
| Missing .env | Copy from `.env.example` |
| Connection failed | Verify `GRAPHQL_ENDPOINT` is accessible |
| Auth errors | Check `GRAPHQL_AUTH_TOKEN` is valid |
| Port in use | Change `MCP_PORT` in `.env` |

## 🛠️ Development

### Adding New Features
1. Modify `server.py` or `server_http.py`
2. Add tool to `@server.list_tools()`
3. Implement handler in `@server.call_tool()`
4. Update documentation

### Testing Changes
```bash
# Run verification
python test_setup.py

# Test locally
python server_http.py
curl http://localhost:8000/health
```

## 📝 Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `GRAPHQL_ENDPOINT` | Yes | GraphQL API URL | `https://api.example.com/graphql` |
| `GRAPHQL_AUTH_TOKEN` | No | Bearer token | `your_token_here` |
| `GRAPHQL_HEADERS` | No | Custom headers (JSON) | `{"X-API-Key": "key"}` |
| `MCP_HOST` | No | HTTP server host | `0.0.0.0` |
| `MCP_PORT` | No | HTTP server port | `8000` |

## 🌟 Highlights

- **Zero Configuration**: Works out of the box with minimal setup
- **Self-Documenting**: Introspection provides complete API documentation
- **LLM-Friendly**: Response format optimized for LLM understanding
- **Flexible Deployment**: Run locally or as a service
- **Production Ready**: Proper error handling and logging
- **Well Documented**: Multiple documentation files and examples

## 📄 License

MIT License - Feel free to use and modify

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 📞 Support

For issues, questions, or contributions:
- Check documentation files
- Review scripts/example_client.py
- Run test_setup.py
- Open GitHub issue

---

**Built with ❤️ for the MCP community**
