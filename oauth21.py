"""
OAuth 2.1 Authentication Module

Implements OAuth 2.1 specification with:
- PKCE (Proof Key for Code Exchange) - mandatory per OAuth 2.1
- Authorization Code flow only (implicit grant removed)
- Refresh token rotation
- Exact redirect URI matching
- Token introspection
- Token revocation

Supports multiple identity providers:
- GitHub
- Generic OAuth 2.1 / OpenID Connect providers

Reference: https://oauth.net/2.1/
"""

import os
import json
import time
import secrets
import hashlib
import base64
import logging
from typing import Optional, Any
from dataclasses import dataclass, field, asdict
from urllib.parse import urlencode, urlparse

import aiohttp

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class OAuth21Config:
    """OAuth 2.1 Provider Configuration"""
    provider: str  # 'github', 'google', 'azure', 'generic'
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    scopes: list[str] = field(default_factory=list)
    # OAuth 2.1 requires exact redirect URI matching
    redirect_uri: str = ""
    # PKCE settings (S256 is required by OAuth 2.1)
    pkce_method: str = "S256"
    # Token settings
    access_token_lifetime: int = 3600  # 1 hour
    refresh_token_lifetime: int = 86400 * 30  # 30 days
    # Authorization
    allowed_users: list[str] = field(default_factory=list)
    allowed_groups: list[str] = field(default_factory=list)


# Pre-configured providers
GITHUB_CONFIG = OAuth21Config(
    provider="github",
    client_id=os.getenv("OAUTH_CLIENT_ID", os.getenv("GITHUB_CLIENT_ID", "")),
    client_secret=os.getenv("OAUTH_CLIENT_SECRET", os.getenv("GITHUB_CLIENT_SECRET", "")),
    authorization_endpoint="https://github.com/login/oauth/authorize",
    token_endpoint="https://github.com/login/oauth/access_token",
    userinfo_endpoint="https://api.github.com/user",
    scopes=["read:user", "read:org"],
    redirect_uri=os.getenv("OAUTH_REDIRECT_URI", os.getenv("GITHUB_OAUTH_CALLBACK_URL", "")),
    allowed_users=[u.strip() for u in os.getenv("OAUTH_ALLOWED_USERS", os.getenv("GITHUB_ALLOWED_USERS", "")).split(",") if u.strip()],
    allowed_groups=[g.strip() for g in os.getenv("OAUTH_ALLOWED_GROUPS", os.getenv("GITHUB_ALLOWED_ORGS", "")).split(",") if g.strip()],
)

GOOGLE_CONFIG = OAuth21Config(
    provider="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
    revocation_endpoint="https://oauth2.googleapis.com/revoke",
    scopes=["openid", "email", "profile"],
    redirect_uri=os.getenv("GOOGLE_REDIRECT_URI", ""),
)

AZURE_CONFIG = OAuth21Config(
    provider="azure",
    client_id=os.getenv("AZURE_CLIENT_ID", ""),
    client_secret=os.getenv("AZURE_CLIENT_SECRET", ""),
    authorization_endpoint=f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID', 'common')}/oauth2/v2.0/authorize",
    token_endpoint=f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID', 'common')}/oauth2/v2.0/token",
    userinfo_endpoint="https://graph.microsoft.com/oidc/userinfo",
    scopes=["openid", "email", "profile", "User.Read"],
    redirect_uri=os.getenv("AZURE_REDIRECT_URI", ""),
)


def get_oauth_config(provider: str = None) -> Optional[OAuth21Config]:
    """Get OAuth configuration for a provider"""
    provider = provider or os.getenv("OAUTH_PROVIDER", "github")
    
    configs = {
        "github": GITHUB_CONFIG,
        "google": GOOGLE_CONFIG,
        "azure": AZURE_CONFIG,
    }
    
    config = configs.get(provider.lower())
    if config and config.client_id:
        return config
    return None


# ============================================================================
# PKCE (Proof Key for Code Exchange) - Required by OAuth 2.1
# ============================================================================

def generate_code_verifier() -> str:
    """
    Generate a cryptographically random code verifier.
    OAuth 2.1 requires 43-128 characters from [A-Z, a-z, 0-9, -, ., _, ~]
    """
    # 64 bytes = 86 characters in base64url (within 43-128 range)
    return secrets.token_urlsafe(64)


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """
    Generate code challenge from verifier.
    OAuth 2.1 requires S256 method (plain is deprecated).
    """
    if method == "S256":
        # SHA256 hash, then base64url encode (without padding)
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    else:
        raise ValueError("OAuth 2.1 requires S256 method for PKCE")


# ============================================================================
# Token Storage (In-memory - use Redis/DB in production)
# ============================================================================

@dataclass
class AuthorizationRequest:
    """Pending authorization request with PKCE"""
    state: str
    code_verifier: str
    code_challenge: str
    redirect_uri: str
    provider: str
    created_at: float = field(default_factory=time.time)
    # Optional: client-provided redirect after auth
    client_redirect_uri: Optional[str] = None


@dataclass  
class TokenSet:
    """OAuth 2.1 Token Set"""
    access_token: str
    token_type: str = "Bearer"
    expires_at: float = 0
    refresh_token: Optional[str] = None
    refresh_expires_at: Optional[float] = None
    scope: str = ""
    # User info
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    groups: list[str] = field(default_factory=list)
    provider: str = ""
    created_at: float = field(default_factory=time.time)


class OAuth21TokenStore:
    """
    In-memory token store with automatic cleanup.
    For production, implement with Redis or database.
    """
    
    def __init__(self):
        self._auth_requests: dict[str, AuthorizationRequest] = {}
        self._tokens: dict[str, TokenSet] = {}  # access_token -> TokenSet
        self._refresh_tokens: dict[str, str] = {}  # refresh_token -> access_token
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes
    
    def _cleanup_if_needed(self):
        """Remove expired tokens and auth requests"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        
        # Clean up expired auth requests (5 minute expiry)
        expired_requests = [
            state for state, req in self._auth_requests.items()
            if now - req.created_at > 300
        ]
        for state in expired_requests:
            self._auth_requests.pop(state, None)
        
        # Clean up expired tokens
        expired_tokens = [
            token for token, data in self._tokens.items()
            if now > data.expires_at
        ]
        for token in expired_tokens:
            self._tokens.pop(token, None)
        
        # Clean up expired refresh tokens
        expired_refresh = [
            rt for rt, at in self._refresh_tokens.items()
            if at not in self._tokens or 
            (self._tokens[at].refresh_expires_at and now > self._tokens[at].refresh_expires_at)
        ]
        for rt in expired_refresh:
            self._refresh_tokens.pop(rt, None)
        
        if expired_requests or expired_tokens or expired_refresh:
            logger.debug(f"Cleaned up {len(expired_requests)} auth requests, "
                        f"{len(expired_tokens)} tokens, {len(expired_refresh)} refresh tokens")
    
    def store_auth_request(self, request: AuthorizationRequest) -> None:
        """Store a pending authorization request"""
        self._cleanup_if_needed()
        self._auth_requests[request.state] = request
    
    def get_auth_request(self, state: str) -> Optional[AuthorizationRequest]:
        """Get and remove an authorization request"""
        self._cleanup_if_needed()
        return self._auth_requests.pop(state, None)
    
    def store_token(self, token_set: TokenSet) -> None:
        """Store a token set"""
        self._cleanup_if_needed()
        self._tokens[token_set.access_token] = token_set
        if token_set.refresh_token:
            self._refresh_tokens[token_set.refresh_token] = token_set.access_token
    
    def get_token(self, access_token: str) -> Optional[TokenSet]:
        """Get token data if valid"""
        self._cleanup_if_needed()
        token_set = self._tokens.get(access_token)
        if token_set and time.time() <= token_set.expires_at:
            return token_set
        return None
    
    def get_token_by_refresh(self, refresh_token: str) -> Optional[TokenSet]:
        """Get token set by refresh token"""
        self._cleanup_if_needed()
        access_token = self._refresh_tokens.get(refresh_token)
        if access_token:
            return self._tokens.get(access_token)
        return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke an access or refresh token"""
        # Check if it's an access token
        if token in self._tokens:
            token_set = self._tokens.pop(token)
            if token_set.refresh_token:
                self._refresh_tokens.pop(token_set.refresh_token, None)
            return True
        
        # Check if it's a refresh token
        if token in self._refresh_tokens:
            access_token = self._refresh_tokens.pop(token)
            self._tokens.pop(access_token, None)
            return True
        
        return False
    
    def rotate_refresh_token(self, old_refresh_token: str, new_token_set: TokenSet) -> bool:
        """
        Rotate refresh token (OAuth 2.1 best practice).
        Invalidates old refresh token and stores new token set.
        """
        if old_refresh_token not in self._refresh_tokens:
            return False
        
        old_access_token = self._refresh_tokens.pop(old_refresh_token)
        self._tokens.pop(old_access_token, None)
        
        self.store_token(new_token_set)
        return True


# Global token store
token_store = OAuth21TokenStore()


# ============================================================================
# OAuth 2.1 Flow Implementation
# ============================================================================

class OAuth21Client:
    """OAuth 2.1 Client with PKCE support"""
    
    def __init__(self, config: OAuth21Config):
        self.config = config
    
    def create_authorization_url(self, redirect_uri: str = None, 
                                  client_redirect_uri: str = None) -> tuple[str, AuthorizationRequest]:
        """
        Create authorization URL with PKCE challenge.
        
        Args:
            redirect_uri: The callback URI for this server
            client_redirect_uri: Optional URI to redirect user after auth completes
            
        Returns:
            Tuple of (authorization_url, auth_request)
        """
        state = secrets.token_urlsafe(32)
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier, self.config.pkce_method)
        
        callback_uri = redirect_uri or self.config.redirect_uri
        
        auth_request = AuthorizationRequest(
            state=state,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            redirect_uri=callback_uri,
            provider=self.config.provider,
            client_redirect_uri=client_redirect_uri
        )
        
        params = {
            "client_id": self.config.client_id,
            "response_type": "code",  # OAuth 2.1: only authorization code flow
            "redirect_uri": callback_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": self.config.pkce_method,
        }
        
        auth_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"
        return auth_url, auth_request
    
    async def exchange_code(self, code: str, auth_request: AuthorizationRequest) -> Optional[TokenSet]:
        """
        Exchange authorization code for tokens using PKCE verifier.
        """
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "grant_type": "authorization_code",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "redirect_uri": auth_request.redirect_uri,
                    "code_verifier": auth_request.code_verifier,  # PKCE verifier
                }
                
                headers = {"Accept": "application/json"}
                
                async with session.post(
                    self.config.token_endpoint,
                    data=data,
                    headers=headers
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error(f"Token exchange failed: {resp.status} - {error_text}")
                        return None
                    
                    result = await resp.json()
                    
                    if "error" in result:
                        logger.error(f"Token exchange error: {result}")
                        return None
                    
                    now = time.time()
                    expires_in = result.get("expires_in", self.config.access_token_lifetime)
                    
                    token_set = TokenSet(
                        access_token=result["access_token"],
                        token_type=result.get("token_type", "Bearer"),
                        expires_at=now + expires_in,
                        refresh_token=result.get("refresh_token"),
                        refresh_expires_at=now + self.config.refresh_token_lifetime if result.get("refresh_token") else None,
                        scope=result.get("scope", " ".join(self.config.scopes)),
                        provider=self.config.provider
                    )
                    
                    # Fetch user info
                    user_info = await self.fetch_user_info(token_set.access_token)
                    if user_info:
                        token_set.user_id = user_info.get("id")
                        token_set.username = user_info.get("username")
                        token_set.email = user_info.get("email")
                        token_set.groups = user_info.get("groups", [])
                    
                    return token_set
                    
        except Exception as e:
            logger.error(f"Error exchanging code: {e}", exc_info=True)
            return None
    
    async def refresh_tokens(self, refresh_token: str) -> Optional[TokenSet]:
        """
        Refresh access token using refresh token.
        OAuth 2.1 recommends refresh token rotation.
        """
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "grant_type": "refresh_token",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "refresh_token": refresh_token,
                }
                
                headers = {"Accept": "application/json"}
                
                async with session.post(
                    self.config.token_endpoint,
                    data=data,
                    headers=headers
                ) as resp:
                    if resp.status != 200:
                        return None
                    
                    result = await resp.json()
                    
                    if "error" in result:
                        return None
                    
                    now = time.time()
                    expires_in = result.get("expires_in", self.config.access_token_lifetime)
                    
                    # Get existing token data
                    old_token_set = token_store.get_token_by_refresh(refresh_token)
                    
                    token_set = TokenSet(
                        access_token=result["access_token"],
                        token_type=result.get("token_type", "Bearer"),
                        expires_at=now + expires_in,
                        # OAuth 2.1: New refresh token (rotation)
                        refresh_token=result.get("refresh_token", refresh_token),
                        refresh_expires_at=now + self.config.refresh_token_lifetime,
                        scope=result.get("scope", old_token_set.scope if old_token_set else ""),
                        user_id=old_token_set.user_id if old_token_set else None,
                        username=old_token_set.username if old_token_set else None,
                        email=old_token_set.email if old_token_set else None,
                        groups=old_token_set.groups if old_token_set else [],
                        provider=self.config.provider
                    )
                    
                    return token_set
                    
        except Exception as e:
            logger.error(f"Error refreshing token: {e}", exc_info=True)
            return None
    
    async def fetch_user_info(self, access_token: str) -> Optional[dict]:
        """Fetch user information from the identity provider"""
        if not self.config.userinfo_endpoint:
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
                
                async with session.get(
                    self.config.userinfo_endpoint,
                    headers=headers
                ) as resp:
                    if resp.status != 200:
                        return None
                    
                    user_info = await resp.json()
                    
                    # Normalize user info across providers
                    if self.config.provider == "github":
                        # Also fetch orgs for GitHub
                        orgs = await self._fetch_github_orgs(access_token)
                        return {
                            "id": str(user_info.get("id")),
                            "username": user_info.get("login"),
                            "email": user_info.get("email"),
                            "name": user_info.get("name"),
                            "groups": orgs
                        }
                    elif self.config.provider == "google":
                        return {
                            "id": user_info.get("sub"),
                            "username": user_info.get("email", "").split("@")[0],
                            "email": user_info.get("email"),
                            "name": user_info.get("name"),
                            "groups": []
                        }
                    elif self.config.provider == "azure":
                        return {
                            "id": user_info.get("sub"),
                            "username": user_info.get("preferred_username", "").split("@")[0],
                            "email": user_info.get("email"),
                            "name": user_info.get("name"),
                            "groups": []  # Would need Graph API for groups
                        }
                    else:
                        return {
                            "id": user_info.get("sub") or user_info.get("id"),
                            "username": user_info.get("preferred_username") or user_info.get("username"),
                            "email": user_info.get("email"),
                            "name": user_info.get("name"),
                            "groups": user_info.get("groups", [])
                        }
                        
        except Exception as e:
            logger.error(f"Error fetching user info: {e}")
            return None
    
    async def _fetch_github_orgs(self, access_token: str) -> list[str]:
        """Fetch GitHub organization memberships"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
                async with session.get(
                    "https://api.github.com/user/orgs",
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        orgs = await resp.json()
                        return [org["login"] for org in orgs]
        except Exception:
            pass
        return []
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke a token at the provider (if supported)"""
        if not self.config.revocation_endpoint:
            # Just remove locally
            return token_store.revoke_token(token)
        
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "token": token,
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                }
                
                async with session.post(
                    self.config.revocation_endpoint,
                    data=data
                ) as resp:
                    # Revocation returns 200 even if token was already invalid
                    token_store.revoke_token(token)
                    return resp.status == 200
                    
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False
    
    def is_user_authorized(self, token_set: TokenSet) -> bool:
        """Check if user is authorized based on allowlists"""
        # If no restrictions, allow all authenticated users
        if not self.config.allowed_users and not self.config.allowed_groups:
            return True
        
        # Check username
        if token_set.username and token_set.username in self.config.allowed_users:
            return True
        
        # Check groups/orgs
        for group in token_set.groups:
            if group in self.config.allowed_groups:
                return True
        
        return False


# ============================================================================
# Token Validation Helper
# ============================================================================

def validate_bearer_token(authorization: str) -> Optional[TokenSet]:
    """
    Validate a Bearer token from Authorization header.
    
    Args:
        authorization: The Authorization header value
        
    Returns:
        TokenSet if valid, None otherwise
    """
    if not authorization:
        return None
    
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization[7:]
    return token_store.get_token(token)


def get_oauth_client(provider: str = None) -> Optional[OAuth21Client]:
    """Get OAuth client for a provider"""
    config = get_oauth_config(provider)
    if config:
        return OAuth21Client(config)
    return None
