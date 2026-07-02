"""
Mount the built React dashboard on a FastAPI app with SPA routing support.

Starlette 0.49+ no longer serves index.html for unknown paths when using
StaticFiles(html=True). Register API routes first, then call mount_frontend().
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

DEFAULT_DIST = Path(__file__).resolve().parent / "frontend" / "dist"


def mount_frontend(app: FastAPI, dist_dir: Path | None = None) -> None:
    dist = Path(dist_dir or DEFAULT_DIST)
    index = dist / "index.html"

    if not index.is_file():
        raise RuntimeError(
            f"Frontend build not found at {dist}. "
            "Run: cd frontend && npm install && npm run build"
        )

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="frontend-assets")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_spa(full_path: str) -> FileResponse:
        if full_path:
            candidate = dist / full_path
            if candidate.is_file():
                return FileResponse(candidate)
        return FileResponse(index)
