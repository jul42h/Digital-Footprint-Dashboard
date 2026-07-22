"""Self-contained authentication & authorization system.

Separate SQLite database, separate router, separate from the DynamoDB-backed
dashboard code in app.py. Nothing outside this package should need to know
how auth is implemented internally — only the exports here.
"""

from .routes import router

__all__ = ["router"]
