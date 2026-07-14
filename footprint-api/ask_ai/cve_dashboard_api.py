"""
CVE Risk Dashboard API.

Exposes an HTTP endpoint that the dashboard frontend calls to get an
AI-generated summary for a set of CVE ids. This service does NOT call
Amazon Bedrock directly -- it invokes the existing "AI Risk Analyzer"
Lambda synchronously via boto3 and relays the result.

ARCHITECTURE NOTE: this deliberately uses IAM-authenticated
    boto3 lambda_client.invoke(), not API Gateway or a Lambda Function URL.
This service already runs with AWS credentials (an IAM role if hosted on
EC2/ECS/similar, or an IAM user's keys otherwise), so a direct, IAM-signed
invoke gives the same security boundary as a SigV4-authenticated HTTP
endpoint would, without the extra infrastructure (API Gateway resources,
routes, another layer of auth to configure).

PREREQUISITE (not code): the IAM role/user this service runs as must have
an attached policy granting "lambda:InvokeFunction" on the target Lambda's
ARN, e.g.:
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "lambda:InvokeFunction",
        "Resource": "arn:aws:lambda:<region>:<account-id>:function:<function-name>"
      }]
    }
"""

from __future__ import annotations

import json
import logging
import os
from asyncio import to_thread
from typing import List, Literal, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIG -- set these via environment variables, do not hardcode.
# ============================================================================

# The deployed name (or ARN) of the AI Risk Analyzer Lambda function.
LAMBDA_FUNCTION_NAME = os.environ.get("CVE_ANALYZER_LAMBDA_NAME", "ai-risk-analyzer")

# The AWS region the LAMBDA FUNCTION ITSELF is deployed in (NOT the Bedrock
# model region -- those are independent, as established when building the
# Lambda). This is just which region's Lambda control plane to call.
LAMBDA_INVOKE_REGION = os.environ.get("CVE_ANALYZER_LAMBDA_REGION", "us-west-2")

# The Lambda function's own configured timeout (Configuration -> General
# configuration -> Timeout), in seconds. This MUST be kept in sync with
# whatever is actually set on the Lambda -- it's used below to size the
# boto3 client's read timeout so this service doesn't give up on the
# connection before Lambda has a chance to finish and respond.
LAMBDA_CONFIGURED_TIMEOUT_SECONDS = int(
    os.environ.get("CVE_ANALYZER_LAMBDA_TIMEOUT_SECONDS", "60")
)

# Max CVE ids accepted per request. Matches the Lambda's own MAX_FINDINGS
# cap; enforcing it here too gives the caller immediate feedback (a 422)
# instead of a silent server-side truncation.
MAX_CVE_IDS_PER_REQUEST = 5


# ============================================================================
# Boto3 Lambda client
# ============================================================================
# read_timeout is set comfortably ABOVE the Lambda's own configured timeout.
# If this were left at boto3's default (60s) and the Lambda's timeout were
# raised above that, this client would abandon the HTTP connection before
# Lambda even finished -- producing a confusing client-side timeout even
# though the Lambda invocation might have succeeded moments later.
#
# retries are disabled (max_attempts=1, i.e. exactly one attempt, no
# retries). This call is NOT safely retryable: each successful invocation
# triggers a real, billed Amazon Bedrock inference call. A transient
# network blip during boto3's own retry logic could otherwise cause the
# same request to invoke Bedrock twice without the caller knowing.
_boto_config = Config(
    read_timeout=LAMBDA_CONFIGURED_TIMEOUT_SECONDS + 15,
    connect_timeout=10,
    retries={"max_attempts": 1},
)

_lambda_client = boto3.client(
    "lambda", region_name=LAMBDA_INVOKE_REGION, config=_boto_config
)


# ============================================================================
# Router + schemas (mounted into the main Footprint Dashboard API)
# ============================================================================

router = APIRouter(tags=["cve-analysis"])


class AnalyzeCVEsRequest(BaseModel):
    cve_ids: List[str] = Field(
        ...,
        min_length=1,
        max_length=MAX_CVE_IDS_PER_REQUEST,
        description="CVE identifiers to analyze, e.g. ['CVE-2026-12345'].",
    )
    # brief = home strip (short executive); detail = panel / CVE page (analyst depth).
    # Relayed to Lambda so its prompt can match the dashboard surface.
    mode: Literal["brief", "detail"] = Field(
        default="detail",
        description="Output style: brief (1–2 sentences) or detail (full analyst write-up).",
    )

    @field_validator("cve_ids")
    @classmethod
    def normalize_cve_ids(cls, value: List[str]) -> List[str]:
        normalized: List[str] = []
        seen: set[str] = set()
        for raw in value:
            cve_id = raw.strip().upper()
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            normalized.append(cve_id)
        if not normalized:
            raise ValueError("At least one CVE id is required.")
        if len(normalized) > MAX_CVE_IDS_PER_REQUEST:
            raise ValueError(f"At most {MAX_CVE_IDS_PER_REQUEST} CVE ids are allowed.")
        return normalized


class AnalyzeCVEsResponse(BaseModel):
    status: str
    invocation_source: Optional[str] = None
    reason: Optional[str] = None
    cve_ids_analyzed: List[str] = []
    total_valid_cve_ids: Optional[int] = None
    ai_summary: Optional[str] = None
    mode: Optional[str] = None


# ============================================================================
# Lambda invocation helper
# ============================================================================

def _invoke_analyzer_lambda(payload: dict) -> dict:
    """
    Synchronously invoke the AI Risk Analyzer Lambda and return its parsed
    response payload.

    This function makes a BLOCKING network call (boto3 has no native async
    support) and must always be run off the event loop via
    asyncio.to_thread -- see the endpoint below. Calling this directly from
    an `async def` route would stall every other request this service is
    handling for the full duration of the Lambda invocation (which can be
    many seconds, given it's waiting on a model response).
    """
    if not LAMBDA_FUNCTION_NAME:
        # Fail fast and clearly if the operator forgot to configure this,
        # rather than letting boto3 raise an opaque error deeper down.
        logger.error("CVE_ANALYZER_LAMBDA_NAME is not configured.")
        raise HTTPException(
            status_code=503,
            detail="Analysis service is not configured (missing Lambda function name).",
        )

    try:
        response = _lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except (BotoCoreError, ClientError) as exc:
        # This branch covers errors that prevent the Lambda from executing
        # at all: permissions issues, throttling, the client timing out
        # while waiting, network errors, etc. -- NOT errors raised by the
        # Lambda's own code (those come back as FunctionError, handled below).
        logger.error("Failed to invoke Lambda %s: %s", LAMBDA_FUNCTION_NAME, exc)
        raise HTTPException(
            status_code=502,
            detail="Could not reach the analysis service. Please try again shortly.",
        )

    raw_payload = response["Payload"].read()

    try:
        result = json.loads(raw_payload)
    except json.JSONDecodeError:
        logger.error("Lambda returned a non-JSON payload: %r", raw_payload)
        raise HTTPException(
            status_code=502, detail="Received a malformed response from the analysis service."
        )

    if response.get("FunctionError"):
        # The Lambda ran but raised an exception. Its payload is an error
        # object: {"errorMessage": ..., "errorType": ..., "stackTrace": [...]}
        # -- NOT the normal {"status": ..., "ai_summary": ...} shape.
        error_type = result.get("errorType", "UnknownError")
        error_message = result.get("errorMessage", "The analysis function raised an error.")
        logger.error(
            "Lambda %s raised %s: %s | payload=%s",
            LAMBDA_FUNCTION_NAME,
            error_type,
            error_message,
            result,
        )

        if error_type == "RuntimeError":
            # Matches the Lambda's own RuntimeError for a missing/misconfigured
            # Bedrock API key -- an operator problem, not the caller's fault.
            raise HTTPException(
                status_code=503,
                detail="Analysis service is misconfigured. Please contact an administrator.",
            )
        if error_type in ("ValueError", "TypeError"):
            # Matches the Lambda's own input-validation errors (bad/missing
            # cve_ids shape) -- this IS the caller's fault, surface as 400.
            raise HTTPException(status_code=400, detail=error_message)

        # Anything else (Bedrock/model call failure, unexpected exception).
        # Include Lambda's errorType/message so operators can fix config without
        # digging through CloudWatch for every dashboard failure.
        raise HTTPException(
            status_code=502,
            detail=(
                f"The analysis service failed to process this request "
                f"({error_type}: {error_message})"
            ),
        )

    return result


# ============================================================================
# Routes
# ============================================================================

@router.post("/api/cve-analysis", response_model=AnalyzeCVEsResponse)
async def analyze_cves(request: AnalyzeCVEsRequest) -> dict:
    """
    Request an AI-generated summary for a set of CVE ids.

    Relays cve_ids + mode to the Lambda and returns its response. mode selects
    prompt style: brief (home) vs detail (panel / CVE detail page).
    """
    payload = {"cve_ids": request.cve_ids, "mode": request.mode}

    result = await to_thread(_invoke_analyzer_lambda, payload)
    if isinstance(result, dict) and "mode" not in result:
        result = {**result, "mode": request.mode}
    return result
