"""FastAPI dependencies: who is making this request, and are they allowed to?

`get_current_user` re-checks the database on every request rather than
trusting the role embedded in the JWT payload. That costs one SQLite lookup
per request (negligible for a local file), but it means a role change or a
disabled account takes effect on the user's very next request instead of
waiting up to 60 minutes for their access token to expire on its own.

Two distinct failure modes, matching the spec exactly:
  - no/invalid/expired token, or the account no longer exists/is disabled -> 401
  - valid token, but the wrong role for this endpoint                     -> 403
"""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from .database import get_session
from .jwt import ExpiredSignatureError, InvalidTokenError, decode_access_token
from .models import User, UserRole

# auto_error=False: a missing header would otherwise make FastAPI's HTTPBearer
# raise 403, but the spec calls for 401 on "not authenticated" and reserves
# 403 for "authenticated but wrong role". Raising it ourselves below keeps
# that distinction correct.
_bearer_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    session: Session = Depends(get_session),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or not credentials.credentials:
        raise unauthorized

    try:
        payload = decode_access_token(credentials.credentials)
    except ExpiredSignatureError:
        unauthorized.detail = "Access token has expired."
        raise unauthorized
    except InvalidTokenError:
        unauthorized.detail = "Invalid access token."
        raise unauthorized

    user_id = payload.get("sub")
    user = session.get(User, int(user_id)) if user_id is not None else None
    if user is None or not user.is_active:
        unauthorized.detail = "User no longer exists or is disabled."
        raise unauthorized

    return user


def require_role(*allowed_roles: UserRole):
    """Dependency factory: `Depends(require_role(UserRole.ADMIN))`."""

    def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(r.value for r in allowed_roles)}.",
            )
        return user

    return _check


# Convenience aliases matching the three permission tiers from the spec:
#   Admin   -> full access, manage users
#   Analyst -> view dashboard, findings, AI summary, reports
#   Viewer  -> read-only dashboard
# Any authenticated user (Viewer and up) can use plain `get_current_user`
# directly — there's no lower tier to exclude.
require_admin = require_role(UserRole.ADMIN)
require_analyst_or_admin = require_role(UserRole.ADMIN, UserRole.ANALYST)
