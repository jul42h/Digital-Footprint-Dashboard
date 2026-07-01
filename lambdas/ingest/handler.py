"""S3 trigger Lambda: ingest Shodan export → DynamoDB snapshot + S3 parquet for Athena.

Wire to s3://{RawDataBucket}/ingest/*.xlsx or *.json
"""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DATA_LAMBDA = os.environ.get("DATA_ACCESS_LAMBDA", "")
CURATED_BUCKET = os.environ.get("CURATED_BUCKET", "")

lambda_client = boto3.client("lambda")
s3 = boto3.client("s3")


def _invoke_data_lambda(payload: dict) -> dict:
    if not DATA_LAMBDA:
        raise RuntimeError("DATA_ACCESS_LAMBDA not configured")
    response = lambda_client.invoke(
        FunctionName=DATA_LAMBDA,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(response["Payload"].read().decode("utf-8"))
    if response.get("FunctionError"):
        raise RuntimeError(body.get("errorMessage", "data lambda error"))
    if "body" in body:
        return json.loads(body["body"]) if isinstance(body["body"], str) else body["body"]
    return body


def handler(event: dict, context: Any) -> dict:
    processed = []
    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        logger.info("Ingesting s3://%s/%s", bucket, key)

        # For production: parse xlsx/json, transform, write parquet to curated bucket
        # then invoke data lambda to refresh snapshot. This stub records the event.
        meta = {
            "bucket": bucket,
            "key": key,
            "ingestedAt": datetime.now(timezone.utc).isoformat(),
            "curatedBucket": CURATED_BUCKET,
        }

        if CURATED_BUCKET:
            s3.put_object(
                Bucket=CURATED_BUCKET,
                Key=f"ingest-manifest/{key.replace('/', '_')}.json",
                Body=json.dumps(meta).encode("utf-8"),
                ContentType="application/json",
            )

        if DATA_LAMBDA:
            _invoke_data_lambda({"action": "refresh"})

        processed.append(meta)

    return {"status": "ok", "processed": processed}
