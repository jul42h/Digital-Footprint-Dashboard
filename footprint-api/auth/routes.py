"""FastAPI router for authentication and user management.

Mounted at /api/v1/auth in app.py — matches this project's existing
/api/v1/* convention for the dashboard endpoints.

Access token: returned in the JSON body. Meant to be held in memory on the
frontend (never localStorage) and sent as `Authorization: Bearer <token>`.

Refresh token: never appears in a JSON response. It's set as an HttpOnly,
Secure, SameSite=Lax cookie scoped to this router's own path, so page
JavaScript can never read or exfiltrate it — the browser attaches it
automatically to requests under /api/v1/auth, and the frontend never has to
manage it directly.
"""

from __future__ import annotations

import os
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session

from . import services
from .database import get_session
from .dependencies import get_client_ip, get_current_user, require_admin
from .models import User
from .schemas import (
    AccessTokenResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    UserCreate,
    UserRead,
    UserUpdate,
)
from .security import check_login_rate_limit
from .services import REFRESH_TOKEN_EXPIRE_DAYS

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

REFRESH_COOKIE_NAME = "df_refresh_token"
REFRESH_COOKIE_PATH = "/api/v1/auth"
# Modern browsers treat "localhost" as a secure context even over plain HTTP,
# so secure=True still works for local dev at http://localhost:8000. It will
# NOT be sent if you test against a raw LAN IP over HTTP instead — set
# AUTH_COOKIE_SECURE=0 for that case, never in a real deployment.
_COOKIE_SECURE = os.environ.get("AUTH_COOKIE_SECURE", "true").lower() not in {"0", "false", "no"}


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


@router.post("/login", response_model=AccessTokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AccessTokenResponse:
    ip_address = get_client_ip(request)
    if not check_login_rate_limit(ip_address):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in a minute.",
        )

    user, access_token, refresh_token, expires_in = services.login(
        session, username=payload.username, password=payload.password, ip_address=ip_address
    )
    _set_refresh_cookie(response, refresh_token)
    return AccessTokenResponse(
        access_token=access_token, expires_in=expires_in, username=user.username, role=user.role
    )


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AccessTokenResponse:
    raw_refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token present.")

    ip_address = get_client_ip(request)
    user, access_token, new_refresh_token, expires_in = services.refresh_access_token(
        session, raw_refresh_token=raw_refresh_token, ip_address=ip_address
    )
    _set_refresh_cookie(response, new_refresh_token)
    return AccessTokenResponse(
        access_token=access_token, expires_in=expires_in, username=user.username, role=user.role
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    raw_refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    services.logout(
        session,
        raw_refresh_token=raw_refresh_token,
        username=current_user.username,
        ip_address=get_client_ip(request),
    )
    _clear_refresh_cookie(response)
    return MessageResponse(message="Logged out.")


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    services.change_password(
        session,
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip_address=get_client_ip(request),
    )
    return MessageResponse(message="Password changed. Other sessions have been signed out.")


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> MessageResponse:
    services.forgot_password(session, email=payload.email, ip_address=get_client_ip(request))
    # Same message regardless of whether the email is on file — see services.forgot_password.
    return MessageResponse(message="If that email is registered, password reset instructions have been sent.")


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("/users", response_model=List[UserRead], dependencies=[Depends(require_admin)])
def list_users(session: Session = Depends(get_session)) -> List[User]:
    return services.list_users(session)


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    session: Session = Depends(get_session),
    admin: User = Depends(require_admin),
) -> User:
    return services.create_user(
        session, payload=payload, actor_username=admin.username, ip_address=get_client_ip(request)
    )


@router.put("/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    session: Session = Depends(get_session),
    admin: User = Depends(require_admin),
) -> User:
    return services.update_user(
        session, user_id=user_id, payload=payload, actor_username=admin.username,
        ip_address=get_client_ip(request),
    )


@router.delete("/users/{user_id}", response_model=MessageResponse)
def delete_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    admin: User = Depends(require_admin),
) -> MessageResponse:
    services.delete_user(
        session, user_id=user_id, actor_username=admin.username, ip_address=get_client_ip(request)
    )
    return MessageResponse(message="User deleted.")
