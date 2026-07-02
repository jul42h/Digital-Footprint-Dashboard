"""
Footprint Dashboard API — FastAPI + uvicorn.

Serves:
  - DynamoDB-backed JSON API for the React dashboard
  - The built React UI from ../frontend/dist

RUN
---
    pip3 install -r requirements.txt
    export DYNAMODB_TABLE_NAME=enriched-database
    export AWS_REGION=us-west-2

    # Build the frontend once (from repo root):
    #   npm run build

    uvicorn app:app --reload --port 8000
    # open http://localhost:8000
"""

from __future__ import annotations

import logging
import os
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from dashboard_transform import findings_to_dashboard

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from frontend_mount import mount_frontend

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "enriched-database")
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")

FRONTEND_DIST = Path(os.environ.get("FRONTEND_DIST", REPO_ROOT / "frontend" / "dist"))

CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:8000"
).split(",")

_table = boto3.resource("dynamodb", region_name=AWS_REGION).Table(TABLE_NAME)

_dashboard_cache: Optional[Dict[str, Any]] = None

# ----------------------------------------------------------------------
# DynamoDB helpers
# ----------------------------------------------------------------------


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    return value


def scan_all() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {}
    try:
        while True:
            resp = _table.scan(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "ResourceNotFoundException":
            raise HTTPException(
                status_code=503,
                detail=(
                    f"DynamoDB table '{TABLE_NAME}' was not found in region '{AWS_REGION}'. "
                    "Set AWS_REGION and DYNAMODB_TABLE_NAME to match your table."
                ),
            ) from exc
        raise HTTPException(status_code=503, detail=f"DynamoDB error: {code}") from exc
    except BotoCoreError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not reach AWS. Check your credentials with `aws configure`.",
        ) from exc
    return _json_safe(items)


def query_ip(ip: str) -> List[Dict[str, Any]]:
    resp = _table.query(KeyConditionExpression=Key("ip").eq(ip))
    return _json_safe(resp.get("Items", []))


def get_item(ip: str, cve_id: str) -> Optional[Dict[str, Any]]:
    resp = _table.get_item(Key={"ip": ip, "cve_id": cve_id})
    item = resp.get("Item")
    return _json_safe(item) if item else None


def load_dashboard(force_refresh: bool = False) -> Dict[str, Any]:
    global _dashboard_cache
    if _dashboard_cache is None or force_refresh:
        _dashboard_cache = findings_to_dashboard(scan_all())
    return _dashboard_cache


# ----------------------------------------------------------------------
# FastAPI app + routes
# ----------------------------------------------------------------------

app = FastAPI(title="Footprint Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
@app.get("/api/v1/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "table": TABLE_NAME}


@app.get("/api/v1/dashboard")
def dashboard() -> Dict[str, Any]:
    try:
        return load_dashboard()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to build dashboard payload")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/v1/dashboard/refresh")
def refresh_dashboard() -> Dict[str, Any]:
    data = load_dashboard(force_refresh=True)
    return {"status": "refreshed", "records": data["stats"]["totalCVEs"]}


@app.get("/findings")
def list_findings(ip: Optional[str] = None) -> Dict[str, Any]:
    items = query_ip(ip) if ip else scan_all()
    return {"count": len(items), "items": items}


@app.get("/findings/{ip}/{cve_id}")
def get_finding(ip: str, cve_id: str) -> Dict[str, Any]:
    item = get_item(ip, cve_id)
    if item is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return item


# ----------------------------------------------------------------------
# Static frontend (register API routes above first)
# ----------------------------------------------------------------------

if FRONTEND_DIST.is_dir():
    mount_frontend(app, FRONTEND_DIST)
else:
    @app.get("/")
    def frontend_missing() -> Dict[str, str]:
        return {
            "message": "Frontend build not found.",
            "expected_path": str(FRONTEND_DIST),
            "build_command": "npm run build",
        }
