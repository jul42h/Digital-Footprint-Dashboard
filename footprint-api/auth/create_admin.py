"""One-time CLI to create the first admin account.

Everything in this system now requires being logged in, and only an admin
can create other users through the API — so the very first account has to
be created directly against the database, before the API is even useful.

Run from the footprint-api directory:
    py -m auth.create_admin

Or non-interactively (e.g. scripted setup):
    py -m auth.create_admin --username admin --email admin@example.com --password '...'

Prefer the interactive prompt over --password when a human is running this —
a password passed as a CLI argument is left sitting in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlmodel import Session, select

from . import security
from .database import create_db_and_tables, engine
from .models import User, UserRole


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username")
    parser.add_argument("--email")
    parser.add_argument(
        "--password",
        help="Avoid this outside of scripts — it's left in shell history. Omit it to be prompted instead.",
    )
    args = parser.parse_args()

    username = args.username or input("Admin username: ").strip()
    email = args.email or input("Admin email: ").strip()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Admin password: ")
        if password != getpass.getpass("Confirm password: "):
            print("Passwords did not match.", file=sys.stderr)
            return 1

    try:
        security.validate_password_length(password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    create_db_and_tables()

    with Session(engine) as session:
        existing = session.exec(
            select(User).where((User.username == username) | (User.email == email))
        ).first()
        if existing is not None:
            print(
                f"Error: a user with that username or email already exists (id={existing.id}).",
                file=sys.stderr,
            )
            return 1

        user = User(
            username=username,
            email=email,
            password_hash=security.hash_password(password),
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        new_id = user.id

    print(f"Created admin user '{username}' (id={new_id}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
