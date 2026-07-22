"""SQLModel table definitions for the authentication system.

These live in their own SQLite database (see database.py) and are completely
separate from the DynamoDB tables the rest of the app reads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Current UTC time as a *naive* datetime.

    SQLite (via SQLAlchemy's default DATETIME type) silently drops tzinfo on
    write — confirmed empirically: storing an aware UTC datetime and reading
    it back returns a naive one. Comparing a naive value against
    `datetime.now(timezone.utc)` later raises TypeError. Rather than fight
    that, every datetime column in this module is naive-but-UTC by
    convention: always produced by this helper, never mixed with
    timezone-aware values or local time.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    password_hash: str
    role: UserRole = Field(default=UserRole.VIEWER)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    last_login: Optional[datetime] = None

    # Account-lockout bookkeeping, required by the "lock out after repeated
    # failed logins" security requirement. Not in the original example
    # table — added so security.py has somewhere to persist this state.
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = None


class RefreshToken(SQLModel, table=True):
    """A server-side record of an issued refresh token.

    Only a hash of the token is stored, never the raw value — a leaked
    database row shouldn't hand out a usable credential. Logout / revocation
    just flips `revoked=True`; nothing needs deleting for that to take effect.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    token_hash: str = Field(unique=True, index=True)
    expires_at: datetime
    created_at: datetime = Field(default_factory=utcnow)
    revoked: bool = Field(default=False)


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: Optional[str] = Field(default=None, index=True)
    action: str = Field(index=True)
    ip_address: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)
    success: bool
    details: Optional[str] = None
