# GitHub OAuth Authentication Guide

This guide explains how to enable and configure GitHub OAuth authentication for the GraphQL MCP Server.

## Overview

GitHub OAuth authentication provides:
- Secure access control to the MCP server
- User authentication via GitHub accounts
- Organization-based access control
- Token-based session management

## Quick Start

### 1. Create a GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in the details:
   - **Application name**: GraphQL MCP Server
   - **Homepage URL**: Your server URL (e.g., `https://mcp.your-domain.com`)
   - **Authorization callback URL**: `https://mcp.your-domain.com/auth/callback`
4. Click **"Register application"**
5. Copy the **Client ID**
6. Generate and copy a new **Client Secret**

### 2. Configure Environment Variables

```bash
# Enable GitHub authentication
GITHUB_AUTH_ENABLED=true

# Your OAuth App credentials
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here

# Optional: Explicit callback URL
GITHUB_OAUTH_CALLBACK_URL=https://mcp.your-domain.com/auth/callback
```

### 3. Configure Access Control (Optional)

```bash
# Allow specific GitHub users
GITHUB_ALLOWED_USERS=octocat,defunkt,mojombo

# Allow members of specific organizations
GITHUB_ALLOWED_ORGS=github,microsoft

# Token expiry (default: 24 hours)
AUTH_TOKEN_EXPIRY=86400
```

> **Note**: If neither `GITHUB_ALLOWED_USERS` nor `GITHUB_ALLOWED_ORGS` is set, any authenticated GitHub user can access the server.

## Authentication Flow

### Browser-Based Flow

1. User visits `/auth/login`
2. User is redirected to GitHub for authentication
3. After approval, GitHub redirects to `/auth/callback`
4. Server exchanges code for access token
5. Server verifies user/org permissions
6. Server issues a session token

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │────▶│  MCP    │────▶│ GitHub  │────▶│  MCP    │
│ Browser │     │ /login  │     │  OAuth  │     │/callback│
└─────────┘     └─────────┘     └─────────┘     └─────────┘
                                                      │
                                                      ▼
                                               ┌─────────────┐
                                               │ Auth Token  │
                                               │   Issued    │
                                               └─────────────┘
```

### API-Based Flow

For programmatic access:

```bash
# 1. Get the OAuth URL
curl http://localhost:8000/auth/login \
  -H "Accept: application/json"

# Response:
# {"auth_url": "https://github.com/login/oauth/authorize?...", "state": "..."}

# 2. Complete OAuth in browser, get token from callback

# 3. Use token for API requests
curl http://localhost:8000/tools \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## API Endpoints

### `GET /auth/login`

Initiates OAuth login flow.

**Query Parameters:**
- `redirect_uri` (optional): URL to redirect after successful auth

**Response (JSON, if `Accept: application/json`):**
```json
{
  "auth_url": "https://github.com/login/oauth/authorize?...",
  "state": "random_state_string"
}
```

**Response (Browser):** Redirects to GitHub OAuth

### `GET /auth/callback`

OAuth callback endpoint. Handles the GitHub redirect.

**Query Parameters:**
- `code`: Authorization code from GitHub
- `state`: State parameter for CSRF protection

**Response:**
```json
{
  "success": true,
  "token": "your_session_token",
  "user": "github_username",
  "expires_in": 86400,
  "message": "Use this token in the Authorization header: Bearer <token>"
}
```

### `GET /auth/status`

Check current authentication status.

**Headers:**
- `Authorization: Bearer <token>` (optional)

**Response (Authenticated):**
```json
{
  "auth_enabled": true,
  "authenticated": true,
  "user": "github_username",
  "expires_at": 1732636800.0
}
```

**Response (Not Authenticated):**
```json
{
  "auth_enabled": true,
  "authenticated": false,
  "login_url": "/auth/login"
}
```

### `POST /auth/logout`

Invalidate current session token.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

## Using with MCP Clients

### VS Code

Add the token to your MCP server configuration:

```json
{
  "mcp.servers": {
    "graphql": {
      "type": "http",
      "url": "https://mcp.your-domain.com",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

### Claude Desktop

For Claude Desktop, you'll need a helper script that handles authentication:

```bash
#!/bin/bash
# mcp-auth-proxy.sh
TOKEN="your_token_here"
curl -N -H "Authorization: Bearer $TOKEN" https://mcp.your-domain.com/sse
```

## Docker Configuration

Add OAuth variables to your Docker Compose:

```yaml
# docker-compose.yml
services:
  graphql-mcp:
    image: graphql-mcp-server:latest
    ports:
      - "8000:8000"
    environment:
      - GRAPHQL_ENDPOINT=${GRAPHQL_ENDPOINT}
      - GITHUB_AUTH_ENABLED=true
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - GITHUB_ALLOWED_ORGS=my-org
```

## Kubernetes Configuration

Add secrets for OAuth credentials:

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: graphql-mcp-secret
  namespace: graphql-mcp
type: Opaque
stringData:
  GRAPHQL_ENDPOINT: "https://api.github.com/graphql"
  GITHUB_AUTH_ENABLED: "true"
  GITHUB_CLIENT_ID: "your_client_id"
  GITHUB_CLIENT_SECRET: "your_client_secret"
  GITHUB_ALLOWED_ORGS: "your-org"
```

## Security Best Practices

### 1. Use HTTPS

Always run the server behind HTTPS in production:

```nginx
server {
    listen 443 ssl;
    server_name mcp.your-domain.com;
    
    ssl_certificate /etc/ssl/certs/mcp.crt;
    ssl_certificate_key /etc/ssl/private/mcp.key;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 2. Protect Client Secrets

Never commit OAuth secrets to version control:

```bash
# .gitignore
.env
*.env.local
```

Use environment variables or secret management:

```bash
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id mcp-oauth --query SecretString

# HashiCorp Vault
vault kv get -field=client_secret secret/mcp/oauth
```

### 3. Limit Token Lifetime

For sensitive environments, reduce token lifetime:

```bash
# 1 hour expiry
AUTH_TOKEN_EXPIRY=3600
```

### 4. Restrict Access

Always configure allowed users or organizations:

```bash
# Most restrictive: specific users only
GITHUB_ALLOWED_USERS=admin1,admin2

# Organization-based access
GITHUB_ALLOWED_ORGS=my-company
```

### 5. Monitor Authentication

Enable debug logging to monitor auth attempts:

```bash
LOG_LEVEL=DEBUG
```

Look for:
```
INFO - User octocat authenticated successfully
WARNING - Unauthorized user attempted login: malicious_user
```

## Troubleshooting

### "Invalid or expired state"

The OAuth state parameter expired (5 minute timeout) or was invalid.

**Solution**: Start the login flow again.

### "User not authorized"

The authenticated user is not in the allowed users or organizations list.

**Solution**: Add the user to `GITHUB_ALLOWED_USERS` or ensure they're a member of an allowed organization.

### "Failed to exchange code for token"

GitHub rejected the authorization code.

**Causes**:
- Invalid client secret
- Code already used
- Code expired

**Solution**: Check credentials and try again.

### Token Not Working

**Check**:
1. Token format: `Authorization: Bearer <token>` (with "Bearer " prefix)
2. Token expiry: Check `/auth/status`
3. Token validity: Tokens are stored in memory, server restart invalidates all tokens

## Production Considerations

### Token Storage

The current implementation stores tokens in memory. For production:

1. **Redis**: Store tokens in Redis for persistence and multi-instance support
2. **Database**: Use PostgreSQL/MySQL for durable storage
3. **JWT**: Use signed JWTs to avoid server-side storage

### Rate Limiting

Consider adding rate limiting for auth endpoints:

```python
# Example with slowapi
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.route("/auth/login")
@limiter.limit("10/minute")
async def auth_login(request):
    ...
```

### Audit Logging

Log all authentication events for security audits:

```python
logger.info(f"AUTH_SUCCESS user={username} ip={client_ip}")
logger.warning(f"AUTH_FAILURE reason=not_authorized user={username} ip={client_ip}")
```
