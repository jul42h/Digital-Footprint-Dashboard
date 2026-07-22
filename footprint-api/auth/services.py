"""Business logic for authentication and user management.

Routes stay thin — this module does the actual work: verifying credentials,
issuing/rotating tokens, and writing audit log entries. It raises
HTTPException directly rather than introducing a separate domain-exception
layer, to keep this auth code proportionate to the size of the project;
routes.py just calls these functions and returns what they give back.
"""

from __future__ import annotations

from datetime import timedelta
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlmodel import Session, select

from . import security
from .jwt import ACCESS_TOKEN_MINUTES, create_access_token
from .models import AuditLog, RefreshToken, User, UserRole, utcnow
from .schemas import UserCreate, UserUpdate

REFRESH_TOKEN_EXPIRE_DAYS = 14


def _log(
    session: Session,
    *,
    username: Optional[str],
    action: str,
    ip_address: Optional[str],
    success: bool,
    details: Optional[str] = None,
) -> None:
    session.add(
        AuditLog(username=username, action=action, ip_address=ip_address, success=success, details=details)
    )
    session.commit()


def _issue_tokens(session: Session, user: User) -> Tuple[str, str, int]:
    """Create a fresh access token + a fresh (rotated) refresh token for `user`."""
    access_token = create_access_token(user_id=user.id, username=user.username, role=user.role)

    raw_refresh = security.generate_refresh_token()
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=security.hash_refresh_token(raw_refresh),
            expires_at=utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    session.commit()

    return access_token, raw_refresh, ACCESS_TOKEN_MINUTES * 60


# ---------------------------------------------------------------------------
# Login / logout / refresh
# ---------------------------------------------------------------------------


def login(session: Session, *, username: str, password: str, ip_address: str) -> Tuple[User, str, str, int]:
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password."
    )

    user = session.exec(select(User).where(User.username == username)).first()

    if user is None:
        _log(session, username=username, action="login_failed", ip_address=ip_address,
             success=False, details="unknown username")
        raise generic_error

    if security.is_locked_out(user):
        _log(session, username=username, action="login_failed", ip_address=ip_address,
             success=False, details="account locked")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is temporarily locked due to repeated failed attempts. Try again later.",
        )

    if not user.is_active:
        _log(session, username=username, action="login_failed", ip_address=ip_address,
             success=False, details="account disabled")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account has been disabled. Contact an administrator.",
        )

    if not security.verify_password(password, user.password_hash):
        security.register_failed_login(user)
        session.add(user)
        session.commit()
        _log(session, username=username, action="login_failed", ip_address=ip_address,
             success=False, details="wrong password")
        raise generic_error

    security.register_successful_login(user)
    session.add(user)
    session.commit()
    session.refresh(user)

    access_token, raw_refresh, expires_in = _issue_tokens(session, user)
    _log(session, username=username, action="login_success", ip_address=ip_address, success=True)

    return user, access_token, raw_refresh, expires_in


def refresh_access_token(
    session: Session, *, raw_refresh_token: str, ip_address: str
) -> Tuple[User, str, str, int]:
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token."
    )

    token_hash = security.hash_refresh_token(raw_refresh_token)
    record = session.exec(select(RefreshToken).where(RefreshToken.token_hash == token_hash)).first()

    if record is None or record.revoked or record.expires_at <= utcnow():
        _log(session, username=None, action="refresh_failed", ip_address=ip_address,
             success=False, details="token not found, revoked, or expired")
        raise invalid

    user = session.get(User, record.user_id)
    if user is None or not user.is_active:
        _log(session, username=None, action="refresh_failed", ip_address=ip_address,
             success=False, details="user missing or disabled")
        raise invalid

    # Rotate: the presented token is single-use. Revoking it here means a
    # replayed old refresh token (e.g. after theft) fails on its next use.
    record.revoked = True
    session.add(record)
    session.commit()

    access_token, new_raw_refresh, expires_in = _issue_tokens(session, user)
    _log(session, username=user.username, action="refresh_success", ip_address=ip_address, success=True)

    return user, access_token, new_raw_refresh, expires_in


def logout(session: Session, *, raw_refresh_token: Optional[str], username: str, ip_address: str) -> None:
    if raw_refresh_token:
        token_hash = security.hash_refresh_token(raw_refresh_token)
        record = session.exec(select(RefreshToken).where(RefreshToken.token_hash == token_hash)).first()
        if record is not None:
            record.revoked = True
            session.add(record)
            session.commit()

    _log(session, username=username, action="logout", ip_address=ip_address, success=True)


# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------


def _revoke_all_refresh_tokens(session: Session, user_id: int) -> None:
    tokens = session.exec(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)  # noqa: E712
    ).all()
    for token in tokens:
        token.revoked = True
        session.add(token)


def _has_other_active_admin(session: Session, exclude_user_id: int) -> bool:
    """Is there at least one *other* admin who could still log in and fix
    things, if `exclude_user_id` stopped being admin right now?"""
    other = session.exec(
        select(User).where(
            User.role == UserRole.ADMIN,
            User.is_active == True,  # noqa: E712
            User.id != exclude_user_id,
        )
    ).first()
    return other is not None


def change_password(
    session: Session, *, user: User, current_password: str, new_password: str, ip_address: str
) -> None:
    if not security.verify_password(current_password, user.password_hash):
        _log(session, username=user.username, action="password_change_failed", ip_address=ip_address,
             success=False, details="current password incorrect")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect.")

    user.password_hash = security.hash_password(new_password)
    session.add(user)
    # A password change should end any other session that might exist
    # because the old password was compromised.
    _revoke_all_refresh_tokens(session, user.id)
    session.commit()

    _log(session, username=user.username, action="password_change", ip_address=ip_address, success=True)


def forgot_password(session: Session, *, email: str, ip_address: str) -> None:
    """Placeholder: records the request but does not send an email yet.

    Behaves identically whether or not the email matches an account, so this
    endpoint can't be used to enumerate registered emails.
    """
    user = session.exec(select(User).where(User.email == email)).first()
    _log(
        session,
        username=user.username if user else None,
        action="forgot_password_requested",
        ip_address=ip_address,
        success=True,
        details="placeholder — no email sent" if user else "email not on file",
    )


# ---------------------------------------------------------------------------
# User management (admin)
# ---------------------------------------------------------------------------


def list_users(session: Session) -> List[User]:
    return list(session.exec(select(User)).all())


def create_user(session: Session, *, payload: UserCreate, actor_username: str, ip_address: str) -> User:
    existing = session.exec(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    ).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already in use.")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=security.hash_password(payload.password),
        role=payload.role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    _log(session, username=actor_username, action="user_created", ip_address=ip_address,
         success=True, details=f"created user '{user.username}' with role {user.role.value}")
    return user


def update_user(
    session: Session, *, user_id: int, payload: UserUpdate, actor_username: str, ip_address: str
) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if user.username == actor_username:
        if payload.is_active is False:
            # Same reasoning as the self-delete guard: disabling your own
            # account (especially if you're the only admin) locks you out
            # with no way back in except direct database access.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot disable your own account."
            )
        if (
            payload.role is not None
            and payload.role != UserRole.ADMIN
            and not _has_other_active_admin(session, user.id)
        ):
            # Same failure mode as disabling yourself: if you're the only
            # active admin, demoting yourself away from Admin leaves nobody
            # who can undo it through the app.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You are the only active admin. Promote another account to Admin first.",
            )

    changes: List[str] = []
    if payload.email is not None and payload.email != user.email:
        user.email = payload.email
        changes.append("email")
    if payload.role is not None and payload.role != user.role:
        user.role = payload.role
        changes.append("role")
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        changes.append("is_active")
    if payload.new_password is not None:
        user.password_hash = security.hash_password(payload.new_password)
        changes.append("password")
        # Same reasoning as change_password: an admin-issued reset should
        # end any session relying on the old password.
        _revoke_all_refresh_tokens(session, user.id)

    session.add(user)
    session.commit()
    session.refresh(user)

    _log(session, username=actor_username, action="user_updated", ip_address=ip_address,
         success=True, details=f"updated user '{user.username}': {', '.join(changes) or 'no changes'}")
    return user


def delete_user(session: Session, *, user_id: int, actor_username: str, ip_address: str) -> None:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if user.username == actor_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account."
        )

    tokens = session.exec(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()
    for token in tokens:
        session.delete(token)

    deleted_username = user.username
    session.delete(user)
    session.commit()

    _log(session, username=actor_username, action="user_deleted", ip_address=ip_address,
         success=True, details=f"deleted user '{deleted_username}'")
