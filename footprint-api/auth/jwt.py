"""Access-token creation and verification (PyJWT).

Only the short-lived *access* token is a JWT. The refresh token is a plain
random string tracked server-side (see security.py + models.RefreshToken) —
that's what makes it revocable; a JWT can't be un-issued before it expires
on its own, which is exactly why it's kept short-lived (60 minutes) here.

`exp`/`iat` are passed to PyJWT as explicit integer Unix timestamps rather
than datetime objects, computed from a timezone-aware `datetime.now(timezone.utc)`.
That sidesteps any ambiguity about how a given PyJWT version converts
datetimes internally — the JWT spec defines exp/iat as NumericDate (seconds
since epoch) anyway, so this is the least surprising way to set them.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt as pyjwt
from jwt import ExpiredSignatureError, InvalidTokenError  # re-exported for callers

from .models import UserRole

ACCESS_TOKEN_MINUTES = 60
JWT_ALGORITHM = "HS256"

JWT_SECRET = os.environ.get("AUTH_JWT_SECRET")


def _require_secret() -> str:
    """Fail loudly rather than ever signing tokens with a guessable default."""
    if not JWT_SECRET:
        raise RuntimeError(
            "AUTH_JWT_SECRET is not set. Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(64))"\n'
            "and set it as an environment variable before starting the API."
        )
    return JWT_SECRET


def create_access_token(*, user_id: int, username: str, role: UserRole) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role.value if isinstance(role, UserRole) else role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "type": "access",
    }
    return pyjwt.encode(payload, _require_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and verify an access token.

    Raises `ExpiredSignatureError` or `InvalidTokenError` (both from PyJWT)
    on failure — callers (dependencies.py) map both to HTTP 401.
    """
    payload = pyjwt.decode(token, _require_secret(), algorithms=[JWT_ALGORITHM])
    if payload.get("type") != "access":
        raise InvalidTokenError("Not an access token")
    return payload
