"""Pydantic request/response models for the auth API.

Kept separate from models.py (the SQLModel *table* definitions) so the wire
format (what a client sends/receives) can evolve independently of the
storage schema — e.g. UserRead below deliberately excludes password_hash.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

from .models import UserRole
from .security import validate_password_length

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
# Deliberately a plain regex rather than pydantic's EmailStr, which needs the
# extra `email-validator` package — staying inside the dependency set this
# project asked for. Good enough for admin-created accounts on an internal
# tool with no public signup; not meant as a full RFC 5322 validator.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _check_username(value: str) -> str:
    if not _USERNAME_RE.match(value):
        raise ValueError(
            "Username must be 3-32 characters: letters, numbers, underscore, or hyphen only."
        )
    return value


def _check_email(value: str) -> str:
    if not _EMAIL_RE.match(value):
        raise ValueError("Must be a valid email address.")
    return value.lower()


# ---------------------------------------------------------------------------
# Auth flow
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class AccessTokenResponse(BaseModel):
    """Returned by /login and /refresh.

    The refresh token itself is never part of this response — it's set as
    an HttpOnly cookie instead (see routes.py), so page JavaScript can never
    read it. Only the short-lived access token needs to be JS-visible, to be
    attached as an Authorization header.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: UserRole


class MessageResponse(BaseModel):
    message: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: str) -> str:
        validate_password_length(value)
        return value


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return _check_email(value)


# ---------------------------------------------------------------------------
# User management (admin)
# ---------------------------------------------------------------------------


class UserRead(BaseModel):
    """What any endpoint returns for a user.

    Deliberately excludes password_hash, failed_login_attempts, and
    locked_until — internal bookkeeping that should never leave the server.
    """

    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.VIEWER

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        return _check_username(value)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return _check_email(value)

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        validate_password_length(value)
        return value


class UserUpdate(BaseModel):
    """All fields optional — PUT /users/{id} only changes what's provided.

    `new_password` covers "admin resets a password": the endpoint list in
    the spec doesn't include a separate reset-password route for an admin
    acting on someone else's account, so it lives here instead.
    """

    email: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: Optional[str]) -> Optional[str]:
        return _check_email(value) if value is not None else None

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            validate_password_length(value)
        return value
