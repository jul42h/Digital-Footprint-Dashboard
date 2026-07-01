"""Invoke the data-access Lambda from FastAPI (AWS mode)."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import Settings

logger = logging.getLogger(__name__)


class LambdaInvokeError(RuntimeError):
    pass


def invoke_data_lambda(settings: Settings, payload: dict[str, Any]) -> dict[str, Any]:
    client = boto3.client("lambda", region_name=settings.aws_region)
    try:
        response = client.invoke(
            FunctionName=settings.data_access_lambda_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except (BotoCoreError, ClientError) as exc:
        raise LambdaInvokeError(f"Lambda invoke failed: {exc}") from exc

    raw = response.get("Payload")
    if raw is None:
        raise LambdaInvokeError("Lambda returned no payload")

    body = json.loads(raw.read().decode("utf-8"))

    if response.get("FunctionError"):
        message = body.get("errorMessage", "Unknown Lambda error")
        raise LambdaInvokeError(message)

    # API Gateway-style wrapper from some handlers
    if "statusCode" in body and "body" in body:
        if body["statusCode"] >= 400:
            raise LambdaInvokeError(str(body.get("body", body)))
        inner = body["body"]
        return json.loads(inner) if isinstance(inner, str) else inner

    return body
