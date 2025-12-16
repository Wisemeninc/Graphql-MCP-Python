# GraphQL MCP Server - API Reference

## Server Modes

### Stdio Mode (`server.py`)
- **Transport**: stdin/stdout
- **Use Case**: Direct integration with MCP clients (Claude Desktop, Continue, etc.)
- **Start**: `python server.py` or `./scripts/run.sh stdio`

### HTTP/SSE Mode (`server_http.py`)
- **Transport**: HTTP with Server-Sent Events support
- **Use Case**: Web-based integrations, HTTP clients
- **Start**: `python server_http.py` or `./scripts/run.sh http`
- **Default Port**: 8000

---

## MCP Tools

All tools return responses in the format:
```json
{
  "query_used" | "mutation_used": "<actual GraphQL operation>",
  "variables": {...} | null,
  "result": {...}
}
```

### Tool: `graphql_introspection`

Performs GraphQL introspection to discover the complete schema.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Usage Example:**
```json
{
  "tool": "graphql_introspection",
  "arguments": {}
}
```

**Response:**
```json
{
  "query_used": "GraphQL Introspection Query",
  "result": {
    "__schema": {
      "queryType": {
        "name": "Query"
      },
      "mutationType": {
        "name": "Mutation"
      },
      "types": [
        {
          "kind": "OBJECT",
          "name": "User",
          "fields": [...]
        }
      ]
    }
  }
}
```

---

### Tool: `graphql_get_schema`

Gets the GraphQL schema in human-readable SDL (Schema Definition Language) format.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {},
  "required": []
}
```

**Usage Example:**
```json
{
  "tool": "graphql_get_schema",
  "arguments": {}
}
```

**Response:**
```json
{
  "query_used": "GraphQL Introspection Query (converted to SDL)",
  "result": {
    "schema": "type Query {\n  user(id: ID!): User\n  users: [User!]!\n}\n\ntype User {\n  id: ID!\n  name: String!\n  email: String!\n  posts: [Post!]!\n}\n\ntype Post {\n  id: ID!\n  title: String!\n  content: String!\n  author: User!\n}\n\ntype Mutation {\n  createUser(input: CreateUserInput!): User!\n  updateUser(id: ID!, input: UpdateUserInput!): User!\n}"
  }
}
```

---

### Tool: `graphql_query`

Executes a GraphQL query operation.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "The GraphQL query to execute"
    },
    "variables": {
      "type": "object",
      "description": "Optional variables for the query",
      "default": {}
    }
  },
  "required": ["query"]
}
```

**Usage Example 1 - Simple Query:**
```json
{
  "tool": "graphql_query",
  "arguments": {
    "query": "{ users { id name email } }"
  }
}
```

**Response:**
```json
{
  "query_used": "{ users { id name email } }",
  "variables": null,
  "result": {
    "users": [
      {
        "id": "1",
        "name": "Alice Smith",
        "email": "alice@example.com"
      },
      {
        "id": "2",
        "name": "Bob Johnson",
        "email": "bob@example.com"
      }
    ]
  }
}
```

**Usage Example 2 - Query with Variables:**
```json
{
  "tool": "graphql_query",
  "arguments": {
    "query": "query GetUser($id: ID!) { user(id: $id) { id name email posts { id title } } }",
    "variables": {
      "id": "1"
    }
  }
}
```

**Response:**
```json
{
  "query_used": "query GetUser($id: ID!) { user(id: $id) { id name email posts { id title } } }",
  "variables": {
    "id": "1"
  },
  "result": {
    "user": {
      "id": "1",
      "name": "Alice Smith",
      "email": "alice@example.com",
      "posts": [
        {
          "id": "101",
          "title": "My First Post"
        }
      ]
    }
  }
}
```

---

### Tool: `graphql_mutation`

Executes a GraphQL mutation operation to modify data.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "mutation": {
      "type": "string",
      "description": "The GraphQL mutation to execute"
    },
    "variables": {
      "type": "object",
      "description": "Optional variables for the mutation",
      "default": {}
    }
  },
  "required": ["mutation"]
}
```

**Usage Example 1 - Inline Mutation:**
```json
{
  "tool": "graphql_mutation",
  "arguments": {
    "mutation": "mutation { createUser(name: \"Charlie\", email: \"charlie@example.com\") { id name email } }"
  }
}
```

**Response:**
```json
{
  "mutation_used": "mutation { createUser(name: \"Charlie\", email: \"charlie@example.com\") { id name email } }",
  "variables": null,
  "result": {
    "createUser": {
      "id": "3",
      "name": "Charlie",
      "email": "charlie@example.com"
    }
  }
}
```

**Usage Example 2 - Mutation with Variables:**
```json
{
  "tool": "graphql_mutation",
  "arguments": {
    "mutation": "mutation CreateUser($input: CreateUserInput!) { createUser(input: $input) { id name email } }",
    "variables": {
      "input": {
        "name": "Diana",
        "email": "diana@example.com"
      }
    }
  }
}
```

**Response:**
```json
{
  "mutation_used": "mutation CreateUser($input: CreateUserInput!) { createUser(input: $input) { id name email } }",
  "variables": {
    "input": {
      "name": "Diana",
      "email": "diana@example.com"
    }
  },
  "result": {
    "createUser": {
      "id": "4",
      "name": "Diana",
      "email": "diana@example.com"
    }
  }
}
```

---

## HTTP Endpoints (server_http.py)

### GET `/` or `/health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "server": "graphql-mcp-server"
}
```

---

### GET `/tools`

List all available MCP tools.

**Response:**
```json
{
  "tools": [
    {
      "name": "graphql_introspection",
      "description": "Perform GraphQL introspection...",
      "inputSchema": {...}
    },
    {
      "name": "graphql_query",
      "description": "Execute a GraphQL query...",
      "inputSchema": {...}
    }
  ]
}
```

---

### POST `/execute`

Execute a specific MCP tool.

**Request Body:**
```json
{
  "tool": "graphql_query",
  "arguments": {
    "query": "{ users { id name } }"
  }
}
```

**Response:**
```json
{
  "tool": "graphql_query",
  "result": [
    {
      "type": "text",
      "text": "{\"query_used\": \"{ users { id name } }\", \"variables\": null, \"result\": {...}}"
    }
  ]
}
```

---

### GET `/sse`

Server-Sent Events endpoint for streaming responses.

**Connection:**
```javascript
const eventSource = new EventSource('http://localhost:8000/sse');

eventSource.addEventListener('connected', (e) => {
  console.log('Connected:', JSON.parse(e.data));
});

eventSource.addEventListener('ready', (e) => {
  console.log('Ready:', JSON.parse(e.data));
});

eventSource.addEventListener('ping', (e) => {
  console.log('Ping:', JSON.parse(e.data));
});
```

**Events:**
- `connected`: Initial connection established
- `ready`: Server is ready to accept requests
- `ping`: Keepalive ping (every 30 seconds)
- `error`: Error occurred

---

## Error Handling

### Tool Execution Errors

```json
{
  "type": "text",
  "text": "Error: GRAPHQL_ENDPOINT environment variable is required"
}
```

### HTTP Endpoint Errors

```json
{
  "error": "tool parameter is required"
}
```

**Status Codes:**
- `200`: Success
- `400`: Bad request (missing parameters)
- `500`: Server error (GraphQL or internal error)

---

## Environment Variables

### Required

- `GRAPHQL_ENDPOINT`: The GraphQL API endpoint URL

### Optional

- `GRAPHQL_AUTH_TOKEN`: Bearer token for authentication
- `GRAPHQL_HEADERS`: Custom headers as JSON string
- `MCP_HOST`: HTTP server host (default: `0.0.0.0`)
- `MCP_PORT`: HTTP server port (default: `8000`)

---

## Example Workflows

### Workflow 1: Discover and Query API

1. **Get Schema**
```json
{"tool": "graphql_get_schema", "arguments": {}}
```

2. **Review Schema** → Identify available queries

3. **Execute Query**
```json
{
  "tool": "graphql_query",
  "arguments": {
    "query": "query GetUsers { users { id name email } }"
  }
}
```

### Workflow 2: Create New Record

1. **Introspect Mutations**
```json
{"tool": "graphql_introspection", "arguments": {}}
```

2. **Review Mutation Signature** → Understand required input

3. **Execute Mutation**
```json
{
  "tool": "graphql_mutation",
  "arguments": {
    "mutation": "mutation CreateUser($input: CreateUserInput!) { createUser(input: $input) { id } }",
    "variables": {
      "input": {
        "name": "New User",
        "email": "user@example.com"
      }
    }
  }
}
```

### Workflow 3: Complex Nested Query

```json
{
  "tool": "graphql_query",
  "arguments": {
    "query": "query GetUserWithPosts($userId: ID!, $limit: Int) { user(id: $userId) { id name posts(limit: $limit) { id title comments { id text author { name } } } } }",
    "variables": {
      "userId": "1",
      "limit": 5
    }
  }
}
```

---

## Best Practices

1. **Use Variables**: Always prefer variables over inline values for security and reusability
2. **Request Specific Fields**: Only request the fields you need
3. **Handle Errors**: Check `query_used` field when debugging
4. **Cache Schema**: Introspection results can be cached as schema rarely changes
5. **Validate Input**: Validate variables against schema before execution

---

## Limitations

- Single GraphQL endpoint per server instance
- Synchronous query execution (no parallel batching)
- No subscription support (queries and mutations only)
- Authentication via bearer token or custom headers only

---

## Support & Debugging

Enable detailed logging by setting:
```python
logging.basicConfig(level=logging.DEBUG)
```

Check logs for:
- GraphQL query/mutation details
- HTTP request/response information
- Connection errors
- Authentication issues
