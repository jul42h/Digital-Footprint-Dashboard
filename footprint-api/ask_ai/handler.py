"""Lambda-compatible Ask AI handler.

FastAPI can call these functions in-process (default) or invoke a deployed
Lambda when ASK_AI_LAMBDA_ARN is configured.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ask_ai.analyst import build_ask_response, build_risk_intelligence, from_bedrock_payload
from ask_ai.bedrock_client import invoke_bedrock
from ask_ai.context import build_context
from ask_ai.schemas import AskRequest, AskResponse, RiskIntelligenceResponse

logger = logging.getLogger(__name__)


def _lambda_arn() -> str:
    return os.environ.get("ASK_AI_LAMBDA_ARN", "").strip()


def _use_remote_lambda() -> bool:
    mode = os.environ.get("ASK_AI_MODE", "local").lower()
    return mode == "lambda" and bool(_lambda_arn())


def handle_ask(dashboard: Dict[str, Any], request: AskRequest) -> AskResponse:
    """Orchestrate context retrieval → model → structured response."""
    if _use_remote_lambda():
        return _invoke_lambda_ask(dashboard, request)

    context = build_context(
        dashboard,
        request.question,
        cve_id=request.cve_id,
        host=request.host,
    )
    history = [{"role": m.role, "content": m.content} for m in request.history]

    bedrock_payload = invoke_bedrock(request.question, context, history=history)
    if bedrock_payload is not None:
        deterministic = build_ask_response(request.question, context)
        return from_bedrock_payload(
            bedrock_payload,
            intent=context.get("intent") or "general",
            fallback_risk=deterministic.riskScore,
        )

    return build_ask_response(request.question, context)


def handle_risk_intelligence(dashboard: Dict[str, Any]) -> RiskIntelligenceResponse:
    if _use_remote_lambda():
        return _invoke_lambda_risk(dashboard)

    context = build_context(dashboard, "Summarize today's findings and risk posture.")
    base = build_risk_intelligence(context)

    bedrock_payload = invoke_bedrock(
        "Produce an executive risk intelligence brief for this footprint.",
        context,
    )
    if bedrock_payload is None:
        return base

    # Merge Bedrock narrative onto structured deterministic lists when present
    return RiskIntelligenceResponse(
        summary=str(bedrock_payload.get("summary") or base.summary),
        riskScore=float(bedrock_payload.get("riskScore") or base.riskScore),
        highestRiskAssets=base.highestRiskAssets,
        topCriticalFindings=base.topCriticalFindings,
        threatIntel=[str(x) for x in (bedrock_payload.get("threatIntel") or base.threatIntel)],
        prioritizedRemediation=[
            str(x) for x in (bedrock_payload.get("remediation") or base.prioritizedRemediation)
        ],
        references=[str(x) for x in (bedrock_payload.get("references") or base.references)],
        mode="bedrock",
    )


def lambda_handler(event: Dict[str, Any], _context: Any = None) -> Dict[str, Any]:
    """AWS Lambda entrypoint.

    Expected event:
      {
        "action": "ask" | "risk_intelligence",
        "dashboard": {...},          # optional if Lambda loads its own data
        "question": "...",           # for ask
        "history": [...],
        "cve_id": "...",
        "host": "..."
      }
    """
    action = (event.get("action") or "ask").lower()
    dashboard = event.get("dashboard") or {}

    if action == "risk_intelligence":
        result = handle_risk_intelligence(dashboard)
        return {"statusCode": 200, "body": result.model_dump()}

    request = AskRequest(
        question=str(event.get("question") or ""),
        history=event.get("history") or [],
        cve_id=event.get("cve_id"),
        host=event.get("host"),
    )
    result = handle_ask(dashboard, request)
    return {"statusCode": 200, "body": result.model_dump()}


def _invoke_lambda_ask(dashboard: Dict[str, Any], request: AskRequest) -> AskResponse:
    payload = {
        "action": "ask",
        "dashboard": dashboard,
        "question": request.question,
        "history": [m.model_dump() for m in request.history],
        "cve_id": request.cve_id,
        "host": request.host,
    }
    body = _invoke_lambda(payload)
    return AskResponse.model_validate({**body, "mode": "lambda"})


def _invoke_lambda_risk(dashboard: Dict[str, Any]) -> RiskIntelligenceResponse:
    payload = {"action": "risk_intelligence", "dashboard": dashboard}
    body = _invoke_lambda(payload)
    return RiskIntelligenceResponse.model_validate({**body, "mode": "lambda"})


def _invoke_lambda(payload: Dict[str, Any]) -> Dict[str, Any]:
    region = os.environ.get("AWS_REGION", "us-west-2")
    try:
        client = boto3.client("lambda", region_name=region)
        response = client.invoke(
            FunctionName=_lambda_arn(),
            InvocationType="RequestResponse",
            Payload=json.dumps(payload, default=str).encode("utf-8"),
        )
        raw = json.loads(response["Payload"].read())
        if isinstance(raw, dict) and "body" in raw:
            body = raw["body"]
            return json.loads(body) if isinstance(body, str) else body
        if isinstance(raw, dict):
            return raw
        raise ValueError("Unexpected Lambda payload shape")
    except (ClientError, BotoCoreError, ValueError, json.JSONDecodeError, TypeError) as exc:
        logger.exception("Ask AI Lambda invoke failed")
        raise RuntimeError(f"Ask AI Lambda invoke failed: {exc}") from exc
