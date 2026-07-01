"""DynamoDB + Athena data access Lambda.

Invoked synchronously by the FastAPI API Lambda with payloads like:
  {"action": "get_dashboard"}
  {"action": "refresh"}
  {"action": "query_athena", "query_type": "severity_summary"}
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "cve-dashboard-data")
ATHENA_DB = os.environ.get("ATHENA_DATABASE", "cve_dashboard")
ATHENA_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "primary")
ATHENA_OUTPUT = os.environ.get("ATHENA_OUTPUT_BUCKET", "")

dynamodb = boto3.resource("dynamodb")
athena = boto3.client("athena")
table = dynamodb.Table(TABLE_NAME)


class DecimalEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, Decimal):
            return float(o) if o % 1 else int(o)
        return super().default(o)


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, cls=DecimalEncoder),
    }


def _deserialize(item: dict) -> Any:
    if "payload" in item:
        return json.loads(item["payload"]) if isinstance(item["payload"], str) else item["payload"]
    return item


def get_dashboard() -> dict:
    """Load dashboard snapshot from DynamoDB (PK=SNAPSHOT, SK=dashboard)."""
    result = table.get_item(Key={"PK": "SNAPSHOT", "SK": "dashboard"})
    item = result.get("Item")
    if not item:
        return {
            "ips": [],
            "stats": {},
            "cveRecords": [],
            "lastUpdated": datetime.now(timezone.utc).isoformat(),
            "source": "dynamodb",
        }
    payload = _deserialize(item)
    payload["source"] = "dynamodb"
    return payload


def put_dashboard_snapshot(data: dict) -> None:
    table.put_item(
        Item={
            "PK": "SNAPSHOT",
            "SK": "dashboard",
            "payload": json.dumps(data, cls=DecimalEncoder),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }
    )


def store_ip_records(ips: list[dict]) -> None:
    with table.batch_writer() as batch:
        for ip in ips:
            batch.put_item(
                Item={
                    "PK": "IP",
                    "SK": ip["ip"],
                    "payload": json.dumps(ip, cls=DecimalEncoder),
                    "riskLevel": ip.get("riskLevel", "Informational"),
                    "country": ip.get("country", ""),
                }
            )


def query_athena(query_type: str) -> dict:
    if not ATHENA_OUTPUT:
        return {"error": "ATHENA_OUTPUT_BUCKET not configured", "rows": []}

    queries = {
        "severity_summary": f"""
            SELECT severity, COUNT(*) AS count
            FROM {ATHENA_DB}.cve_records
            GROUP BY severity
            ORDER BY count DESC
        """,
        "country_summary": f"""
            SELECT country, COUNT(DISTINCT ip) AS ip_count
            FROM {ATHENA_DB}.ip_assets
            GROUP BY country
            ORDER BY ip_count DESC
            LIMIT 50
        """,
    }
    sql = queries.get(query_type, queries["severity_summary"]).strip()

    execution = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": ATHENA_DB},
        WorkGroup=ATHENA_WORKGROUP,
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT},
    )
    query_id = execution["QueryExecutionId"]

    for _ in range(60):
        status = athena.get_query_execution(QueryExecutionId=query_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            break
        if state in {"FAILED", "CANCELLED"}:
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", state)
            return {"error": reason, "query_type": query_type, "rows": []}
        time.sleep(1)

    rows: list[dict] = []
    result = athena.get_query_results(QueryExecutionId=query_id)
    headers = [c["VarCharValue"] for c in result["ResultSet"]["Rows"][0]["Data"]]
    for row in result["ResultSet"]["Rows"][1:]:
        values = [c.get("VarCharValue", "") for c in row["Data"]]
        rows.append(dict(zip(headers, values)))

    return {"query_type": query_type, "source": "athena", "rows": rows}


def refresh_from_athena() -> dict:
    """Run Athena ETL query and refresh DynamoDB snapshot metadata."""
    summary = query_athena("severity_summary")
    if summary.get("error"):
        return {"status": "error", "message": summary["error"]}

    dashboard = get_dashboard()
    dashboard["lastUpdated"] = datetime.now(timezone.utc).isoformat()
    dashboard["athenaSummary"] = summary
    put_dashboard_snapshot(dashboard)

    return {
        "status": "ok",
        "message": "Athena query completed; snapshot metadata updated",
        "lastUpdated": dashboard["lastUpdated"],
        "athena": summary,
    }


def handler(event: dict, context: Any) -> dict:
    logger.info("Event: %s", json.dumps(event))

    # Direct invoke from FastAPI
    if "action" in event:
        action = event["action"]
        try:
            if action == "get_dashboard":
                return get_dashboard()
            if action == "refresh":
                return refresh_from_athena()
            if action == "query_athena":
                return query_athena(event.get("query_type", "severity_summary"))
            if action == "put_snapshot":
                put_dashboard_snapshot(event["data"])
                if event.get("ips"):
                    store_ip_records(event["ips"])
                return {"status": "ok", "message": "Snapshot stored"}
            return _response(400, {"error": f"Unknown action: {action}"})
        except Exception as exc:
            logger.exception("Handler error")
            return _response(500, {"error": str(exc)})

    # API Gateway proxy (optional direct route)
    body = event.get("body")
    payload = json.loads(body) if isinstance(body, str) else (body or {})
    return handler({**payload, **event}, context)
