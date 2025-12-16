# GraphQL MCP Server - Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         LLM / Client                             │
│                  (Claude, ChatGPT, Custom App)                   │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 │ MCP Protocol
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌─────────┐            ┌──────────────┐
│ stdio   │            │  HTTP/SSE    │
│ server  │            │   server     │
│         │            │              │
│ server  │            │ server_http  │
│  .py    │            │    .py       │
└────┬────┘            └──────┬───────┘
     │                        │
     │   MCP Tool Handlers    │
     └────────┬───────────────┘
              │
    ┌─────────┴─────────────────────┐
    │                               │
    │    GraphQL MCP Server Core    │
    │                               │
    │  ┌─────────────────────────┐  │
    │  │ • Introspection Tool    │  │
    │  │ • Query Tool            │  │
    │  │ • Mutation Tool         │  │
    │  │ • Schema Tool           │  │
    │  └─────────────────────────┘  │
    │                               │
    └───────────────┬───────────────┘
                    │
                    │ GraphQL Protocol
                    │
    ┌───────────────▼───────────────┐
    │                               │
    │    GQL Client (aiohttp)       │
    │                               │
    │  • Transport Layer            │
    │  • Authentication             │
    │  • Query Execution            │
    │  • Error Handling             │
    │                               │
    └───────────────┬───────────────┘
                    │
                    │ HTTP(S)
                    │
    ┌───────────────▼───────────────┐
    │                               │
    │      GraphQL API Endpoint     │
    │   (Your Database/Service)     │
    │                               │
    └───────────────────────────────┘
```

## Data Flow

### Query Execution Flow

```
1. LLM Request
   │
   ├─→ "Execute graphql_query with { users { id name } }"
   │
   ▼
2. MCP Server
   │
   ├─→ Parse request
   ├─→ Validate tool name
   ├─→ Extract arguments
   │
   ▼
3. GraphQL Client
   │
   ├─→ Build GraphQL request
   ├─→ Add authentication headers
   ├─→ Send HTTP request
   │
   ▼
4. GraphQL API
   │
   ├─→ Validate query
   ├─→ Execute against database
   ├─→ Return data
   │
   ▼
5. Response Processing
   │
   ├─→ Parse GraphQL response
   ├─→ Format as MCP response
   ├─→ Include query_used field
   │
   ▼
6. LLM Response
   │
   └─→ {
         "query_used": "{ users { id name } }",
         "result": { "users": [...] }
       }
```

## Component Details

### 1. Transport Layer

#### Stdio Transport (server.py)
```
┌──────────────────────┐
│   stdin/stdout       │
│   ┌──────────────┐   │
│   │ read_stream  │   │
│   └──────┬───────┘   │
│          │           │
│   ┌──────▼───────┐   │
│   │ MCP Server   │   │
│   └──────┬───────┘   │
│          │           │
│   ┌──────▼───────┐   │
│   │ write_stream │   │
│   └──────────────┘   │
└──────────────────────┘
```

#### HTTP/SSE Transport (server_http.py)
```
┌─────────────────────────┐
│   Starlette App         │
│   ┌──────────────────┐  │
│   │ GET /health      │  │
│   ├──────────────────┤  │
│   │ GET /tools       │  │
│   ├──────────────────┤  │
│   │ POST /execute    │  │
│   ├──────────────────┤  │
│   │ GET /sse         │  │
│   └──────────────────┘  │
│                         │
│   Uvicorn ASGI Server   │
└─────────────────────────┘
```

### 2. Tool Handlers

```
@server.list_tools()
    └─→ Returns tool definitions
        │
        ├─→ graphql_introspection
        ├─→ graphql_get_schema
        ├─→ graphql_query
        └─→ graphql_mutation

@server.call_tool(name, arguments)
    └─→ Routes to appropriate handler
        │
        ├─→ handle_introspection()
        ├─→ handle_get_schema()
        ├─→ handle_query(arguments)
        └─→ handle_mutation(arguments)
```

### 3. GraphQL Client Configuration

```
Environment Variables
    │
    ├─→ GRAPHQL_ENDPOINT
    ├─→ GRAPHQL_AUTH_TOKEN
    └─→ GRAPHQL_HEADERS
        │
        ▼
AIOHTTPTransport
    │
    ├─→ URL
    ├─→ Headers (Auth + Custom)
    └─→ Timeout settings
        │
        ▼
GQL Client
    │
    ├─→ Transport
    ├─→ Schema fetching
    └─→ Query execution
```

## Request/Response Cycle

### Introspection Request

```
Request:
  tool: "graphql_introspection"
  arguments: {}

Processing:
  1. Get GraphQL client
  2. Generate introspection query
  3. Execute query
  4. Format response

Response:
  {
    "query_used": "GraphQL Introspection Query",
    "result": {
      "__schema": { ... }
    }
  }
```

### Query with Variables Request

```
Request:
  tool: "graphql_query"
  arguments: {
    "query": "query GetUser($id: ID!) { user(id: $id) { name } }",
    "variables": {"id": "123"}
  }

Processing:
  1. Get GraphQL client
  2. Parse query string
  3. Validate variables
  4. Execute with gql()
  5. Format response

Response:
  {
    "query_used": "query GetUser($id: ID!) { user(id: $id) { name } }",
    "variables": {"id": "123"},
    "result": {
      "user": {"name": "Alice"}
    }
  }
```

## Error Flow

```
Error Occurrence
    │
    ├─→ Connection Error
    │   └─→ Return: "Error: Cannot connect to endpoint"
    │
    ├─→ Authentication Error
    │   └─→ Return: "Error: Invalid authentication token"
    │
    ├─→ Query Syntax Error
    │   └─→ Return: "Error: GraphQL syntax error at line X"
    │
    └─→ Validation Error
        └─→ Return: "Error: Field 'xyz' not found on type 'User'"
```

## Security Flow

```
Request
    │
    ▼
Environment Variables
    │
    ├─→ Load from .env
    ├─→ Validate GRAPHQL_ENDPOINT
    └─→ Check optional tokens
        │
        ▼
Build Headers
    │
    ├─→ Add Authorization: Bearer {token}
    └─→ Add custom headers
        │
        ▼
HTTPS Connection
    │
    └─→ Encrypted transport to API
```

## Deployment Architectures

### Local Development

```
┌──────────────┐
│   Developer  │
│   Machine    │
│              │
│  ┌────────┐  │
│  │ Claude │  │
│  │Desktop │  │
│  └───┬────┘  │
│      │ stdio │
│  ┌───▼────┐  │
│  │ server │  │
│  │  .py   │  │
│  └───┬────┘  │
│      │ HTTPS │
└──────┼───────┘
       │
    ┌──▼────┐
    │GraphQL│
    │  API  │
    └───────┘
```

### Cloud Deployment

```
┌─────────────┐     ┌──────────────┐
│  Web Client │────▶│ Load Balancer│
└─────────────┘     └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
      ┌───────▼────────┐      ┌────────▼───────┐
      │  MCP Server 1  │      │  MCP Server 2  │
      │ (server_http)  │      │ (server_http)  │
      └───────┬────────┘      └────────┬───────┘
              │                         │
              └────────────┬────────────┘
                           │ HTTPS
                    ┌──────▼──────┐
                    │  GraphQL    │
                    │   Cluster   │
                    └─────────────┘
```

## Performance Considerations

### Caching Strategy

```
Introspection Result
    │
    └─→ Cache in memory
        │
        ├─→ TTL: 1 hour
        └─→ Invalidate on schema change
```

### Connection Pooling

```
GraphQL Client
    │
    └─→ Reuse connections
        │
        ├─→ Pool size: 10
        └─→ Keep-alive: 60s
```

## Monitoring Points

```
1. Request Level
   ├─→ Tool invocations
   ├─→ Execution time
   └─→ Error rate

2. GraphQL Level
   ├─→ Query complexity
   ├─→ Response size
   └─→ API latency

3. System Level
   ├─→ CPU usage
   ├─→ Memory usage
   └─→ Network I/O
```

---

This architecture provides:
- **Flexibility**: Multiple transport options
- **Scalability**: Stateless design allows horizontal scaling
- **Reliability**: Proper error handling at each layer
- **Security**: Token-based authentication and HTTPS support
- **Transparency**: Full query visibility for debugging and learning
