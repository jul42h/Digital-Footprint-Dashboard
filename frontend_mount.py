"""
Mount the built React dashboard on a FastAPI app with SPA routing support.

Starlette 0.49+ no longer serves index.html for unknown paths when using
StaticFiles(html=True). Register API routes first, then call mount_frontend().

Set FRONTEND_DEV_URL (e.g. http://127.0.0.1:5173) to proxy to the Vite dev
server so http://localhost:8000 always matches `npm run dev`.
"""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from pathlib import Path
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request as UrlRequest, urlopen

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

DEFAULT_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

_CACHE_IMMUTABLE = "public, max-age=31536000, immutable"
_CACHE_HTML = "no-cache, no-store, must-revalidate"


def _response_headers(path: Path) -> Dict[str, str]:
    if path.name == "index.html":
        return {"Cache-Control": _CACHE_HTML}
    if path.parent.name == "assets":
        return {"Cache-Control": _CACHE_IMMUTABLE}
    return {"Cache-Control": _CACHE_HTML}


def mount_frontend(app: FastAPI, dist_dir: Path | None = None) -> None:
    dist = Path(dist_dir or DEFAULT_DIST).resolve()
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
            candidate = (dist / full_path).resolve()
            if candidate.is_relative_to(dist) and candidate.is_file():
                return FileResponse(candidate, headers=_response_headers(candidate))
        return FileResponse(index, headers=_response_headers(index))

    logger.info("Serving production frontend from %s", dist)


def _fetch_dev_asset(url: str, method: str) -> Response:
    request = UrlRequest(url, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read()
            content_type = response.headers.get("Content-Type")
            if not content_type:
                guessed, _ = mimetypes.guess_type(url)
                content_type = guessed or "application/octet-stream"
            return Response(
                content=body,
                status_code=response.status,
                media_type=content_type,
                headers={"Cache-Control": _CACHE_HTML},
            )
    except HTTPError as exc:
        body = exc.read()
        content_type = exc.headers.get("Content-Type", "text/plain")
        return Response(content=body, status_code=exc.code, media_type=content_type)
    except URLError as exc:
        logger.warning("Vite dev server unreachable at %s: %s", url, exc.reason)
        return Response(
            content=(
                "Vite dev server is not running. Start it with: npm run dev\n"
                f"Tried: {url}"
            ),
            status_code=503,
            media_type="text/plain",
        )


def mount_frontend_dev_proxy(app: FastAPI, dev_url: str) -> None:
    base = dev_url.rstrip("/") + "/"

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def proxy_to_vite(full_path: str, request: Request) -> Response:
        target = urljoin(base, full_path)
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return await asyncio.to_thread(_fetch_dev_asset, target, request.method)

    logger.info("Proxying frontend to Vite dev server at %s", dev_url)
