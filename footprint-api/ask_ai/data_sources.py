"""Optional Athena / S3 enrichment hooks for Ask AI context.

Today the primary evidence set is the DynamoDB-backed dashboard cache.
These helpers are ready for Lambda deployment when Athena workgroups or
raw S3 scan prefixes are configured.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


def athena_enabled() -> bool:
    return bool(os.environ.get("ATHENA_DATABASE") and os.environ.get("ATHENA_OUTPUT_S3"))


def fetch_athena_rows(sql: str, max_rows: int = 50) -> List[Dict[str, Any]]:
    """Run a short Athena query when configured; otherwise return []."""
    if not athena_enabled():
        return []

    database = os.environ["ATHENA_DATABASE"]
    output = os.environ["ATHENA_OUTPUT_S3"]
    workgroup = os.environ.get("ATHENA_WORKGROUP", "primary")
    region = os.environ.get("AWS_REGION", "us-west-2")

    try:
        client = boto3.client("athena", region_name=region)
        start = client.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": output},
            WorkGroup=workgroup,
        )
        qid = start["QueryExecutionId"]
        # Minimal polling — callers should keep SQL cheap
        for _ in range(30):
            status = client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
            if status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                break
            import time

            time.sleep(0.4)
        if status != "SUCCEEDED":
            logger.warning("Athena query did not succeed: %s", status)
            return []

        result = client.get_query_results(QueryExecutionId=qid, MaxResults=max_rows)
        rows = result.get("ResultSet", {}).get("Rows", [])
        if not rows:
            return []
        headers = [c.get("VarCharValue", "") for c in rows[0].get("Data", [])]
        out: List[Dict[str, Any]] = []
        for row in rows[1:]:
            values = [c.get("VarCharValue") for c in row.get("Data", [])]
            out.append(dict(zip(headers, values)))
        return out
    except (ClientError, BotoCoreError, KeyError) as exc:
        logger.warning("Athena enrichment skipped: %s", exc)
        return []


def fetch_s3_scan_snippet(key: str, max_bytes: int = 32_000) -> Optional[str]:
    """Load a small raw scan artifact from S3 when S3_BUCKET_NAME is set."""
    bucket = os.environ.get("S3_BUCKET_NAME", "").strip()
    if not bucket or not key:
        return None
    region = os.environ.get("AWS_REGION", "us-west-2")
    try:
        client = boto3.client("s3", region_name=region)
        obj = client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read(max_bytes)
        return body.decode("utf-8", errors="replace")
    except (ClientError, BotoCoreError, UnicodeError) as exc:
        logger.warning("S3 enrichment skipped for %s: %s", key, exc)
        return None
