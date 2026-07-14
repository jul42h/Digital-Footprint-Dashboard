"""Amazon Bedrock invocation for cybersecurity analyst responses."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a Senior Cybersecurity Threat Analyst embedded in Fresno State's Digital Footprint Dashboard.

Rules:
- Answer ONLY using the supplied environment context. If data is missing, say what is missing.
- Be evidence-based: cite CVE IDs, CVSS, KEV, EPSS, hosts, ports, and products from context.
- Prioritize remediation and call out active exploitation / internet exposure.
- Identify likely attack paths when evidence supports them.
- Use clear analyst language — no generic chatbot filler.

Respond with ONLY valid JSON matching this schema:
{
  "summary": "string",
  "riskScore": number or null,
  "priority": [{"asset": "string", "reason": "string"}],
  "remediation": ["string"],
  "threatIntel": ["string"],
  "references": ["string"]
}
"""


def bedrock_enabled() -> bool:
    return os.environ.get("BEDROCK_ENABLED", "0").lower() in {"1", "true", "yes"}


def get_model_id() -> str:
    return os.environ.get(
        "BEDROCK_MODEL_ID",
        "anthropic.claude-3-haiku-20240307-v1:0",
    )


def invoke_bedrock(
    question: str,
    context: Dict[str, Any],
    history: Optional[List[Dict[str, str]]] = None,
) -> Optional[Dict[str, Any]]:
    """Call Bedrock; return parsed JSON dict or None on failure/disabled."""
    if not bedrock_enabled():
        return None

    region = os.environ.get("BEDROCK_REGION") or os.environ.get("AWS_REGION", "us-west-2")
    model_id = get_model_id()

    user_payload = {
        "question": question,
        "environmentContext": context,
        "recentHistory": (history or [])[-6:],
    }

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": int(os.environ.get("BEDROCK_MAX_TOKENS", "2048")),
        "temperature": float(os.environ.get("BEDROCK_TEMPERATURE", "0.2")),
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(user_payload, default=str),
                    }
                ],
            }
        ],
    }

    try:
        client = boto3.client("bedrock-runtime", region_name=region)
        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )
        raw = json.loads(response["body"].read())
        text = _extract_text(raw)
        parsed = _parse_json_object(text)
        if parsed is None:
            logger.warning("Bedrock returned non-JSON content; falling back")
            return None
        return parsed
    except (ClientError, BotoCoreError, KeyError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Bedrock invoke failed: %s", exc)
        return None


def _extract_text(raw: Dict[str, Any]) -> str:
    content = raw.get("content") or []
    parts: List[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    if parts:
        return "\n".join(parts)
    # Some models return completion-style payloads
    return str(raw.get("completion") or raw.get("outputText") or "")


def _parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        try:
            data = json.loads(fence.group(1))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
    brace = re.search(r"\{.*\}", text, re.S)
    if brace:
        try:
            data = json.loads(brace.group(0))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
    return None
