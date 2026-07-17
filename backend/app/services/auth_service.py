"""
Auth service — simple API-key middleware.

Keys are loaded from the environment variable SECURITY_API_KEYS as a
comma-separated list.  Set to "*" to disable auth (development mode).
"""
import os
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_raw = os.getenv("SECURITY_API_KEYS", "*")
_VALID_KEYS: set[str] = set() if _raw == "*" else {k.strip() for k in _raw.split(",") if k.strip()}
_AUTH_DISABLED = _raw == "*"


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """FastAPI dependency that enforces API key authentication."""
    if _AUTH_DISABLED:
        return "dev"
    if not api_key or api_key not in _VALID_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Supply your key in the X-API-Key header.",
        )
    return api_key
