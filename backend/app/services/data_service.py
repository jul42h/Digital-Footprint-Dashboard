"""Dashboard data access: Lambda (AWS) or local JSON/Excel fallback."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings
from app.models import DashboardData, DashboardStats
from app.services.lambda_client import LambdaInvokeError, invoke_data_lambda
from app.services.local_loader import load_local_dashboard

logger = logging.getLogger(__name__)


def empty_dashboard() -> DashboardData:
    return DashboardData(
        ips=[],
        stats=DashboardStats(),
        cveRecords=[],
        lastUpdated=datetime.now(timezone.utc).isoformat(),
        source="empty",
    )


def _coerce_dashboard(payload: dict) -> DashboardData:
    return DashboardData.model_validate(payload)


def get_dashboard(settings: Settings) -> DashboardData:
    if settings.environment == "aws":
        try:
            payload = invoke_data_lambda(settings, {"action": "get_dashboard"})
            data = _coerce_dashboard(payload)
            data.source = "dynamodb"
            return data
        except LambdaInvokeError as exc:
            logger.warning("Lambda get_dashboard failed, falling back to local: %s", exc)

    # Local mode: snapshot JSON → Excel → empty
    json_path = Path(settings.local_data_json)
    if not json_path.is_absolute():
        json_path = Path(__file__).resolve().parents[2] / json_path

    if json_path.exists():
        with json_path.open(encoding="utf-8") as f:
            data = _coerce_dashboard(json.load(f))
            data.source = "api"
            return data

    excel_path = Path(settings.local_excel_path)
    if not excel_path.is_absolute():
        excel_path = Path(__file__).resolve().parents[2] / excel_path

    if excel_path.exists():
        data = load_local_dashboard(excel_path)
        data.source = "excel"
        return data

    return empty_dashboard()


def refresh_dashboard(settings: Settings) -> dict:
    """Trigger ingest/Athena refresh via Lambda, or rebuild local snapshot."""
    if settings.environment == "aws":
        try:
            result = invoke_data_lambda(settings, {"action": "refresh"})
            return result
        except LambdaInvokeError as exc:
            logger.warning("Lambda refresh failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    # Local: rebuild JSON from Excel
    excel_path = Path(settings.local_excel_path)
    if not excel_path.is_absolute():
        excel_path = Path(__file__).resolve().parents[2] / excel_path

    if not excel_path.exists():
        return {"status": "error", "message": f"Excel not found: {excel_path}"}

    data = load_local_dashboard(excel_path)
    json_path = Path(settings.local_data_json)
    if not json_path.is_absolute():
        json_path = Path(__file__).resolve().parents[2] / json_path
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(data.model_dump(), f, indent=2)

    return {
        "status": "ok",
        "message": "Local snapshot refreshed from Excel",
        "lastUpdated": data.lastUpdated,
    }


def query_analytics(settings: Settings, query_type: str = "severity_summary") -> dict:
    if settings.environment == "aws":
        return invoke_data_lambda(
            settings,
            {"action": "query_athena", "query_type": query_type},
        )

    data = get_dashboard(settings)
    by_severity: dict[str, int] = {}
    for record in data.cveRecords:
        sev = record.cve.severity
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "query_type": query_type,
        "source": "local",
        "rows": [{"severity": k, "count": v} for k, v in by_severity.items()],
    }
