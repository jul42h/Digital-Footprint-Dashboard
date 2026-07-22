"""SQLite database dedicated to authentication (users, refresh tokens, audit log).

Deliberately separate from the DynamoDB-backed dashboard data in app.py /
dashboard_transform.py — this file only ever creates or reads the auth.db
SQLite file sitting next to it in this package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from sqlmodel import Session, SQLModel, create_engine

from . import models  # noqa: F401  registers User/RefreshToken/AuditLog on SQLModel.metadata

AUTH_DB_PATH = Path(__file__).resolve().parent / "auth.db"
DATABASE_URL = f"sqlite:///{AUTH_DB_PATH}"

# check_same_thread=False is required for SQLite under FastAPI's threaded
# request handling; SQLAlchemy still serializes access per connection.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def create_db_and_tables() -> None:
    """Create auth.db and its tables if they don't exist yet. Called once on API startup."""
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
