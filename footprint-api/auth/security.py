"""Password hashing, refresh-token generation, account lockout, and basic
per-IP login rate limiting.

Password hashing uses bcrypt directly rather than passlib, which has had
version-compatibility breaks with recent bcrypt releases. Refresh tokens are
high-entropy random strings from `secrets` — hashed with SHA-256 before
storage, not bcrypt: bcrypt's deliberate slowness is what makes it right for
low-entropy human passwords, but it buys nothing for an already-random
256+ bit token and would just make every refresh request slower.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

import bcrypt

from .models import User, utcnow

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128  # bcrypt silently ignores bytes past 72; reject long input instead

MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

REFRESH_TOKEN_BYTES = 64  # secrets.token_urlsafe(64) -> ~86-char token, 512 bits of entropy

_RATE_LIMIT_WINDOW_SECONDS = 60.0
_RATE_LIMIT_MAX_ATTEMPTS_PER_IP = 10
# In-memory and per-process — resets on restart. That's fine here: this is a
# coarse "slow down a spray across many usernames from one IP" guard, not the
# thing that actually stops a single account being brute-forced (that's the
# per-account lockout below, which is durable in SQLite).
_login_attempts_by_ip: Dict[str, List[float]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def validate_password_length(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")


def hash_password(password: str) -> str:
    validate_password_length(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed/legacy hash — treat as a failed check, not a crash.
        return False


# ---------------------------------------------------------------------------
# Refresh tokens (random opaque strings, not JWTs — see models.RefreshToken)
# ---------------------------------------------------------------------------


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Account lockout
# ---------------------------------------------------------------------------


def is_locked_out(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > utcnow()


def register_failed_login(user: User) -> None:
    """Mutates `user` in place; the caller commits the session."""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = utcnow() + LOCKOUT_DURATION


def register_successful_login(user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = utcnow()


# ---------------------------------------------------------------------------
# Per-IP login rate limiting
# ---------------------------------------------------------------------------


def check_login_rate_limit(ip_address: str) -> bool:
    """Return True if `ip_address` is still within the allowed attempt rate."""
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW_SECONDS
    attempts = _login_attempts_by_ip[ip_address]
    attempts[:] = [t for t in attempts if t > window_start]
    if len(attempts) >= _RATE_LIMIT_MAX_ATTEMPTS_PER_IP:
        return False
    attempts.append(now)
    return True
