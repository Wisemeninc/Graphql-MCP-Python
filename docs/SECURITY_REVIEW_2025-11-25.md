# Security & Code Review Report

**Project:** GraphQL MCP Server  
**Version:** 1.2.0  
**Date:** November 25, 2025  
**Reviewer:** Automated Security Analysis  

---

## Executive Summary

This security review evaluates the GraphQL MCP Server against the OWASP Top 10 (2021), security best practices, and code quality standards. The review identifies potential vulnerabilities, risks, and provides actionable recommendations.

### Overall Risk Assessment: **MEDIUM**

| Category | Risk Level | Issues Found |
|----------|------------|--------------|
| Authentication & Authorization | Medium | 3 |
| Injection Attacks | Low | 2 |
| Security Misconfiguration | Medium | 4 |
| Sensitive Data Exposure | Medium | 3 |
| Infrastructure Security | Low | 2 |

---

## OWASP Top 10 Analysis

### A01:2021 – Broken Access Control ⚠️ MEDIUM

**Findings:**

1. **In-Memory Token Storage (CRITICAL)**
   - **Location:** `server_mcp_http.py` lines 69-70
   - **Issue:** Auth tokens stored in Python dictionaries (`oauth_states`, `auth_tokens`)
   - **Risk:** Token loss on server restart, not suitable for multi-instance deployments
   - **Recommendation:** Use Redis or database for production token storage
   ```python
   # Current (vulnerable)
   oauth_states: dict[str, dict] = {}
   auth_tokens: dict[str, dict] = {}
   
   # Recommended
   # Use Redis: redis.set(f"token:{token}", json.dumps(data), ex=AUTH_TOKEN_EXPIRY)
   ```

2. **CORS Allows All Origins**
   - **Location:** `server_mcp_http.py` lines 1009-1015
   - **Issue:** `allow_origins=["*"]` permits any origin
   - **Risk:** Cross-origin attacks possible
   - **Recommendation:** Restrict to specific allowed origins
   ```python
   # Current (too permissive)
   allow_origins=["*"]
   
   # Recommended
   allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:*").split(",")
   ```

3. **No Rate Limiting**
   - **Issue:** Endpoints lack rate limiting
   - **Risk:** Brute-force attacks on auth, DoS attacks
   - **Recommendation:** Add rate limiting middleware (e.g., `slowapi`)

### A02:2021 – Cryptographic Failures ✅ LOW

**Findings:**

1. **Secure Token Generation** ✓
   - Uses `secrets.token_urlsafe(64)` - cryptographically secure
   - OAuth state uses `secrets.token_urlsafe(32)` - adequate

2. **No HTTPS Enforcement**
   - **Issue:** Server doesn't force HTTPS
   - **Risk:** Token interception in transit
   - **Recommendation:** Add HSTS headers, redirect HTTP to HTTPS
   ```python
   # Add security headers middleware
   response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
   ```

### A03:2021 – Injection ⚠️ MEDIUM

**Findings:**

1. **GraphQL Query Injection**
   - **Location:** `server_mcp_http.py` `handle_query()` function
   - **Issue:** User-provided GraphQL queries executed directly
   - **Risk:** Malicious queries could overload backend, data exfiltration
   - **Mitigation Present:** Uses `gql` library which provides basic validation
   - **Recommendation:** Add query complexity analysis and depth limiting
   ```python
   # Recommended: Add query depth/complexity limits
   from graphql import parse
   from graphql.validation import validate
   
   def validate_query_complexity(query_str: str, max_depth: int = 10):
       # Implement depth checking
       pass
   ```

2. **JSON Parsing**
   - **Location:** Multiple endpoints
   - **Status:** Uses safe `request.json()` - no raw string parsing
   - **Risk:** Low

### A04:2021 – Insecure Design ⚠️ MEDIUM

**Findings:**

1. **Debug Mode in Production**
   - **Location:** `server_mcp_http.py` line 1023
   - **Issue:** `debug=True` in Starlette app creation
   - **Risk:** Exposes stack traces, internal paths
   - **Recommendation:** Make configurable via environment variable
   ```python
   # Current (insecure)
   app = Starlette(debug=True, ...)
   
   # Recommended
   DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"
   app = Starlette(debug=DEBUG_MODE, ...)
   ```

2. **Verbose Error Messages**
   - **Location:** Throughout error handlers
   - **Issue:** Exception details returned to client
   - **Recommendation:** Log full errors, return generic messages to clients

### A05:2021 – Security Misconfiguration ⚠️ MEDIUM

**Findings:**

1. **Default Credentials in Examples**
   - **Location:** `.env.example`
   - **Issue:** Contains placeholder values that could be accidentally used
   - **Recommendation:** Add stronger warnings, use clearly fake values

2. **Docker Health Check Exposes Internal State**
   - **Location:** `Dockerfile` line 37
   - **Issue:** Health check could reveal server is running
   - **Status:** Acceptable for internal use
   - **Recommendation:** Consider separate internal health endpoint

3. **Missing Security Headers**
   - **Issue:** No Content-Security-Policy, X-Frame-Options, etc.
   - **Recommendation:** Add security headers middleware
   ```python
   async def add_security_headers(request, call_next):
       response = await call_next(request)
       response.headers["X-Content-Type-Options"] = "nosniff"
       response.headers["X-Frame-Options"] = "DENY"
       response.headers["X-XSS-Protection"] = "1; mode=block"
       response.headers["Content-Security-Policy"] = "default-src 'self'"
       return response
   ```

4. **Kubernetes Secret in Plain YAML**
   - **Location:** `k8s/secret.yaml`
   - **Issue:** Uses `stringData` (base64 encoding only)
   - **Recommendation:** Use external secrets management (Vault, AWS Secrets Manager)

### A06:2021 – Vulnerable and Outdated Components ✅ LOW

**Findings:**

1. **Dependencies Review**
   ```
   mcp>=0.9.0          - MCP SDK (check for updates)
   gql>=3.5.0          - GraphQL client ✓
   starlette>=0.35.0   - Web framework ✓
   uvicorn>=0.25.0     - ASGI server ✓
   aiohttp>=3.9.0      - HTTP client ✓
   ```

2. **Recommendations:**
   - Add `pip-audit` to CI/CD pipeline
   - Pin exact versions in production
   - Set up Dependabot or Renovate for updates
   ```bash
   # Add to CI
   pip install pip-audit
   pip-audit --require-hashes
   ```

### A07:2021 – Identification and Authentication Failures ⚠️ MEDIUM

**Findings:**

1. **OAuth State Expiry**
   - **Location:** `server_mcp_http.py` line 132
   - **Current:** 5-minute state expiry - adequate
   - **Status:** ✓ Good

2. **Token Lifetime**
   - **Current:** Default 24 hours (`AUTH_TOKEN_EXPIRY`)
   - **Recommendation:** Consider shorter lifetime for high-security deployments
   - **Missing:** No refresh token mechanism

3. **No Session Binding**
   - **Issue:** Tokens not bound to client IP or user agent
   - **Risk:** Token theft usable from any location
   - **Recommendation:** Optional IP binding
   ```python
   auth_tokens[auth_token] = {
       "user": user_info["login"],
       "client_ip": request.client.host,  # Add this
       "user_agent": request.headers.get("user-agent"),  # Add this
       ...
   }
   ```

4. **No Account Lockout**
   - **Issue:** No protection against brute force on OAuth
   - **Note:** Mitigated by GitHub's own rate limiting

### A08:2021 – Software and Data Integrity Failures ✅ LOW

**Findings:**

1. **Docker Image**
   - Uses official `python:3.12-slim` base image ✓
   - No arbitrary code execution vectors found

2. **Dependency Integrity**
   - **Recommendation:** Add hash verification in requirements
   ```
   # requirements.txt with hashes
   mcp==0.9.0 --hash=sha256:...
   ```

### A09:2021 – Security Logging and Monitoring Failures ⚠️ MEDIUM

**Findings:**

1. **Good Logging Practices Present** ✓
   - Authentication attempts logged
   - Tool executions logged
   - Client IPs captured

2. **Missing Security Events:**
   - Failed authentication attempts not separately tracked
   - No alerting mechanism
   - No log aggregation setup
   
3. **Recommendations:**
   ```python
   # Add structured security event logging
   def log_security_event(event_type: str, details: dict):
       security_logger.warning(json.dumps({
           "event": event_type,
           "timestamp": datetime.utcnow().isoformat(),
           **details
       }))
   ```

### A10:2021 – Server-Side Request Forgery (SSRF) ⚠️ MEDIUM

**Findings:**

1. **GraphQL Endpoint Configuration**
   - **Location:** `GRAPHQL_ENDPOINT` environment variable
   - **Risk:** If attacker controls this, SSRF is possible
   - **Mitigation:** Environment variable set at deployment
   - **Status:** Low risk if properly configured

2. **GitHub API Calls**
   - **Location:** `fetch_github_user()`, `exchange_code_for_token()`
   - **Status:** Hardcoded to `api.github.com` - safe ✓

---

## Code Quality Issues

### 1. Unused Import
```python
# Line 12 - hashlib imported but never used
import hashlib
```
**Recommendation:** Remove unused import

### 2. Type Hints Inconsistency
Some functions missing return type hints:
```python
# Missing return type
def cleanup_expired_tokens():  # -> None

# Has return type
def generate_oauth_state() -> str:
```

### 3. Error Handling Improvement
```python
# Current - catches all exceptions
except Exception as e:
    logger.error(f"Error: {str(e)}", exc_info=True)

# Recommended - specific exception handling
except aiohttp.ClientError as e:
    logger.error(f"Network error: {e}")
except json.JSONDecodeError as e:
    logger.error(f"JSON parsing error: {e}")
```

### 4. Magic Numbers
```python
# Line 132 - magic number for state expiry
if current_time - data["created_at"] > 300:

# Recommended
OAUTH_STATE_EXPIRY_SECONDS = 300
if current_time - data["created_at"] > OAUTH_STATE_EXPIRY_SECONDS:
```

---

## Infrastructure Security (Kubernetes)

### Strengths ✅

1. **Pod Security Context**
   - `runAsNonRoot: true`
   - `runAsUser: 1000`
   - `allowPrivilegeEscalation: false`
   - `readOnlyRootFilesystem: true`
   - `capabilities: drop: ALL`

2. **Network Policy**
   - Ingress restricted to ingress-nginx namespace
   - Egress limited to DNS and HTTPS

3. **Resource Limits**
   - Memory: 128Mi-512Mi
   - CPU: 100m-500m

### Improvements Needed

1. **Pod Security Standards**
   ```yaml
   # Add to namespace
   metadata:
     labels:
       pod-security.kubernetes.io/enforce: restricted
   ```

2. **Service Account**
   ```yaml
   # Add to deployment
   spec:
     automountServiceAccountToken: false
     serviceAccountName: graphql-mcp-server
   ```

---

## Dockerfile Security

### Strengths ✅
- Non-root user (`appuser`)
- Slim base image
- No cache directories
- Health check configured

### Improvements

1. **Pin Base Image Digest**
   ```dockerfile
   # Current
   FROM python:3.12-slim
   
   # Recommended
   FROM python:3.12-slim@sha256:<specific-digest>
   ```

2. **Add .dockerignore Check**
   - Verify `.env` and secrets excluded ✓
   - Add `*.pem`, `*.key` patterns

3. **Remove curl in Production**
   ```dockerfile
   # Consider using Python for health check to remove curl
   HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
   ```

---

## Prioritized Recommendations

### Critical (Fix Immediately)

| # | Issue | Location | Effort |
|---|-------|----------|--------|
| 1 | Disable debug mode in production | `server_mcp_http.py:1023` | Low |
| 2 | Add rate limiting | All endpoints | Medium |
| 3 | Restrict CORS origins | `server_mcp_http.py:1010` | Low |

### High Priority (Fix Within Sprint)

| # | Issue | Location | Effort |
|---|-------|----------|--------|
| 4 | Add security headers | Middleware | Low |
| 5 | Implement persistent token storage | Auth module | Medium |
| 6 | Add GraphQL query depth limiting | Query handler | Medium |
| 7 | Remove unused `hashlib` import | Line 12 | Low |

### Medium Priority (Plan for Next Release)

| # | Issue | Location | Effort |
|---|-------|----------|--------|
| 8 | Add token refresh mechanism | Auth flow | High |
| 9 | Implement structured security logging | Logging | Medium |
| 10 | Add pip-audit to CI/CD | Pipeline | Low |
| 11 | External secrets management for K8s | Infrastructure | Medium |

### Low Priority (Best Practices)

| # | Issue | Location | Effort |
|---|-------|----------|--------|
| 12 | Pin Docker base image digest | Dockerfile | Low |
| 13 | Add IP binding for tokens | Auth | Low |
| 14 | Consistent type hints | Codebase | Low |

---

## Compliance Considerations

### GDPR
- User data (GitHub profile) stored in memory tokens
- **Recommendation:** Document data retention policy
- **Recommendation:** Implement token data export endpoint

### SOC 2
- Logging present but not centralized
- Access controls implemented
- **Recommendation:** Add audit trail for all data access

---

## Quick Fixes Code Snippet

```python
# Add this to server_mcp_http.py for immediate security improvements

# 1. Configurable debug mode
DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

# 2. Configurable CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",") or ["*"]

# 3. Security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not DEBUG_MODE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

# 4. OAuth state expiry constant
OAUTH_STATE_EXPIRY_SECONDS = int(os.getenv("OAUTH_STATE_EXPIRY", "300"))

# 5. Update app creation
app = Starlette(
    debug=DEBUG_MODE,
    routes=[...],
    middleware=[
        Middleware(SecurityHeadersMiddleware),
        cors_middleware,
        *([Middleware(GitHubAuthMiddleware)] if GITHUB_AUTH_ENABLED else [])
    ]
)
```

---

## Conclusion

The GraphQL MCP Server has a solid security foundation with:
- Proper OAuth 2.0 implementation
- GitHub-based authentication with org support
- Non-root container execution
- Kubernetes security contexts

Key areas requiring immediate attention:
1. Production debug mode
2. Rate limiting
3. CORS configuration
4. Security headers

The codebase demonstrates security awareness, particularly in the authentication implementation. With the recommended improvements, this server would be suitable for production deployment.

---

**Report Generated:** 2025-11-25  
**Next Review Date:** 2026-02-25 (Quarterly)  
**Classification:** Internal Use Only
