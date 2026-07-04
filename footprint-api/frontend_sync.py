"""Keep the API-served UI in sync with frontend source."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

logger = logging.getLogger(__name__)

WATCH_RELATIVE = ("src", "index.html", "vite.config.ts", "package.json", "package-lock.json")


def watch_paths(repo_root: Path) -> list[Path]:
    frontend = repo_root / "frontend"
    paths: list[Path] = []
    for relative in WATCH_RELATIVE:
        path = frontend / relative
        if path.exists():
            paths.append(path)
    return paths


def source_fingerprint(repo_root: Path) -> str:
    digest = hashlib.sha256()
    for root in sorted(watch_paths(repo_root), key=lambda p: p.as_posix()):
        if root.is_file():
            digest.update(root.as_posix().encode())
            digest.update(root.read_bytes())
            continue
        for file_path in sorted(root.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(repo_root).as_posix()
                digest.update(rel.encode())
                digest.update(file_path.read_bytes())
    return digest.hexdigest()[:24]


def read_build_info(dist_dir: Path) -> dict:
    info_path = dist_dir / "build-info.json"
    if not info_path.is_file():
        return {}
    try:
        return json.loads(info_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_build_info(dist_dir: Path, repo_root: Path, built_at: str | None = None) -> None:
    from datetime import datetime, timezone

    payload = {
        "builtAt": built_at or datetime.now(timezone.utc).isoformat(),
        "sourceHash": source_fingerprint(repo_root),
        "dist": str(dist_dir),
    }
    (dist_dir / "build-info.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def dist_is_stale(dist_dir: Path, repo_root: Path) -> bool:
    index = dist_dir / "index.html"
    if not index.is_file():
        return True

    stored = read_build_info(dist_dir).get("sourceHash")
    if not stored:
        return True

    return stored != source_fingerprint(repo_root)


def vite_dev_available(url: str, timeout: float = 0.75) -> bool:
    try:
        with urlopen(url, timeout=timeout) as response:
            return response.status < 500
    except (URLError, TimeoutError, OSError):
        return False


def run_frontend_build(repo_root: Path) -> bool:
    npm = shutil.which("npm")
    if not npm:
        logger.warning("npm was not found. Build the frontend manually: npm run build")
        return False

    logger.info("Building frontend (npm run build) …")
    try:
        subprocess.run(
            [npm, "run", "build"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Frontend build failed:\n%s", exc.stderr or exc.stdout)
        return False

    dist_dir = repo_root / "frontend" / "dist"
    index = dist_dir / "index.html"
    if not index.is_file():
        logger.error("Frontend build finished but %s was not created", index)
        return False

    write_build_info(dist_dir, repo_root)
    info = read_build_info(dist_dir)
    logger.info("Frontend build ready (%s)", info.get("builtAt", "unknown time"))
    return True


def ensure_frontend_current(
    repo_root: Path,
    dist_dir: Path,
    *,
    always_rebuild: bool = False,
    skip_build: bool = False,
) -> None:
    if skip_build:
        return

    index = dist_dir / "index.html"
    stale = dist_is_stale(dist_dir, repo_root)

    if index.is_file() and not always_rebuild and not stale:
        info = read_build_info(dist_dir)
        logger.info(
            "Serving frontend build from %s (built %s)",
            dist_dir,
            info.get("builtAt", "unknown time"),
        )
        return

    if stale and index.is_file():
        logger.info("Frontend source changed — rebuilding production bundle …")
    elif not index.is_file():
        logger.info("Frontend build not found at %s — building …", dist_dir)

    if not run_frontend_build(repo_root):
        if index.is_file():
            logger.error(
                "Rebuild failed; serving existing bundle at %s (may be outdated). "
                "Run `npm run build` from the repo root.",
                dist_dir,
            )
        else:
            logger.error("Rebuild failed and no frontend bundle is available.")


def resolve_dev_proxy_url(
    explicit_url: str,
    *,
    auto_detect: bool,
    default_url: str = "http://127.0.0.1:5173",
) -> str:
    if explicit_url:
        return explicit_url
    if auto_detect and vite_dev_available(default_url):
        logger.info("Vite dev server detected — proxying UI to %s", default_url)
        return default_url
    return ""
