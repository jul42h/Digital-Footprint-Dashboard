"""
CVE Risk Dashboard API.

Relays dashboard analysis requests to the AI Risk Analyzer Lambda.
Does not call Bedrock / OpenAI directly.

Payload (vital fields only):
  {
    "cve_ids": ["CVE-…"],          # optional if findings present
    "findings": [ {…}, … ],        # structured records for the Lambda (preferred)
    "mode": "brief" | "detail",
    "intent": "brief" | "insights" | "risk_score" | "threat_intel"
              | "critical_findings" | "risk_assets" | "remediate" | "ask_ai",
    "question": "What should we fix first?"  # required only when intent="ask_ai"
  }

The Lambda computes `risk_score` (score/rating/drivers/confidence) itself from
the posture of whatever findings are sent — this API does not compute or pass a
score in either direction, only relays it in the response.
"""

from __future__ import annotations

import json
import logging
import os
import re
from asyncio import to_thread
from typing import Any, Dict, List, Literal, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

LAMBDA_FUNCTION_NAME = os.environ.get("CVE_ANALYZER_LAMBDA_NAME", "ai-risk-analyzer")
LAMBDA_INVOKE_REGION = os.environ.get("CVE_ANALYZER_LAMBDA_REGION", "us-west-2")
LAMBDA_CONFIGURED_TIMEOUT_SECONDS = int(
    os.environ.get("CVE_ANALYZER_LAMBDA_TIMEOUT_SECONDS", "60")
)

# Align with Lambda caps (practical UI payload stays under Lambda maxes).
# Lambda: MAX_INPUT_FINDINGS=1500, MAX_CVE_IDS=25, MAX_DETAIL_FINDINGS=10,
# MAX_QUESTION_CHARS=500. EPSS_NOTABLE=0.5 / EPSS_URGENT=0.9 live only inside
# the Lambda posture/prompts — not dashboard stats.
MAX_CVE_IDS_PER_REQUEST = 25
MAX_FINDINGS_PER_REQUEST = 100
MAX_QUESTION_LENGTH = 500
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)

_HARMONY_FINAL_RE = re.compile(r"<\|channel\|>\s*final\s*<\|message\|>", re.I)
_HARMONY_TOKEN_RE = re.compile(r"<\|[^|]*\|>")
_REASON_BLOCK_RE = re.compile(
    r"<\s*(think|thinking|reasoning|analysis|scratchpad)\b[^>]*>"
    r".*?<\s*/\s*\1\s*>",
    re.I | re.S,
)
_REASON_TAG_RE = re.compile(
    r"<\s*/?\s*(think|thinking|reasoning|analysis|scratchpad|final|commentary)"
    r"\b[^>]*>",
    re.I,
)
_FENCE_RE = re.compile(r"\A\s*```[A-Za-z]*\s*\n(.*?)\n?\s*```\s*\Z", re.S)
_HEADING_RE = re.compile(r"^#{1,4}\s+\S", re.M)
_LEAD_CHANNEL_RE = re.compile(
    r"\A(assistant)?\s*(analysis|commentary|final)\b[:.\s]*", re.I
)
_BOILERPLATE_RE = re.compile(
    r"(?:^|\n)\s*_?Output truncated at the token limit\.?_?\s*(?=\n|$)",
    re.I,
)
# Shown in place of the Lambda's raw truncation marker — deleting it silently
# hid from analysts that a response (e.g. a remediation plan) was cut short.
_TRUNCATION_NOTICE = (
    "\n\n⚠ This response was cut short by the model's length limit — "
    "some content may be missing."
)

AnalysisMode = Literal["brief", "detail"]
AnalysisIntent = Literal[
    "brief",
    "insights",
    "risk_score",
    "threat_intel",
    "critical_findings",
    "risk_assets",
    "remediate",
    "ask_ai",
]

_boto_config = Config(
    read_timeout=LAMBDA_CONFIGURED_TIMEOUT_SECONDS + 15,
    connect_timeout=10,
    retries={"max_attempts": 1},
)

_lambda_client = boto3.client(
    "lambda", region_name=LAMBDA_INVOKE_REGION, config=_boto_config
)

router = APIRouter(tags=["cve-analysis"])


def _sanitize_ai_summary(text: Any) -> Optional[str]:
    """Defense-in-depth mirror of the Lambda's own sanitizing, in case leaked
    scaffolding ever slips past it before reaching the UI."""
    if text is None:
        return None
    cleaned = str(text).replace("\r\n", "\n")

    finals = list(_HARMONY_FINAL_RE.finditer(cleaned))
    if finals:
        cleaned = cleaned[finals[-1].end() :]

    cleaned = _REASON_BLOCK_RE.sub("", cleaned)
    cleaned = _HARMONY_TOKEN_RE.sub("", cleaned)
    cleaned = _REASON_TAG_RE.sub("", cleaned)

    fenced = _FENCE_RE.match(cleaned)
    if fenced:
        cleaned = fenced.group(1)

    heading = _HEADING_RE.search(cleaned)
    if heading and heading.start() > 0:
        cleaned = cleaned[heading.start() :]

    cleaned = _LEAD_CHANNEL_RE.sub("", cleaned.lstrip())
    was_truncated = _BOILERPLATE_RE.search(cleaned) is not None
    cleaned = _BOILERPLATE_RE.sub("\n", cleaned)
    cleaned = re.sub(r"[ \t]+$", "", cleaned, flags=re.M)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    if was_truncated and cleaned:
        cleaned += _TRUNCATION_NOTICE
    return cleaned or None


def _intent_to_mode(intent: AnalysisIntent) -> AnalysisMode:
    return "brief" if intent == "brief" else "detail"


def _mode_to_intent(mode: AnalysisMode) -> AnalysisIntent:
    """Legacy `mode` only distinguishes brief vs. detail; "insights" is the
    Lambda's own default for any unrecognized/absent non-brief intent."""
    return "brief" if mode == "brief" else "insights"


def _normalize_cve_list(value: Optional[List[str]]) -> List[str]:
    if not value:
        return []
    normalized: List[str] = []
    seen: set[str] = set()
    for raw in value:
        cve_id = str(raw).strip().upper()
        if not cve_id or cve_id in seen or not CVE_RE.match(cve_id):
            continue
        seen.add(cve_id)
        normalized.append(cve_id)
        if len(normalized) >= MAX_CVE_IDS_PER_REQUEST:
            break
    return normalized


def _cve_ids_from_findings(findings: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        raw = finding.get("cve_id") or finding.get("original_cve_id")
        cve_id = str(raw or "").strip().upper()
        if not cve_id or cve_id in seen or not CVE_RE.match(cve_id):
            continue
        seen.add(cve_id)
        out.append(cve_id)
        if len(out) >= MAX_CVE_IDS_PER_REQUEST:
            break
    return out


class AnalyzeCVEsRequest(BaseModel):
    cve_ids: Optional[List[str]] = Field(
        default=None,
        max_length=MAX_CVE_IDS_PER_REQUEST,
        description="CVE identifiers. Optional when findings are provided.",
    )
    findings: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        max_length=MAX_FINDINGS_PER_REQUEST,
        description="Structured findings for the Lambda (preferred).",
    )
    mode: Optional[AnalysisMode] = None
    intent: Optional[AnalysisIntent] = None
    question: Optional[str] = Field(
        default=None,
        max_length=MAX_QUESTION_LENGTH,
        description='Free-text question. Required for ask_ai unless question_id is set.',
    )
    question_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description=(
            "Predetermined Ask AI prompt id. Lambda owns the canonical question text."
        ),
    )
    question_params: Optional[Dict[str, str]] = Field(
        default=None,
        description="Template parameters for question_id (e.g. cve_id).",
    )

    @field_validator("cve_ids")
    @classmethod
    def normalize_cve_ids(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        return _normalize_cve_list(value)

    @field_validator("question")
    @classmethod
    def normalize_question(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            return None
        # Match Lambda: reject over-long questions instead of silently truncating
        # mid-thought. The dashboard clamps before send; this guards other clients.
        if len(trimmed) > MAX_QUESTION_LENGTH:
            raise ValueError(
                f"question must be {MAX_QUESTION_LENGTH} characters or fewer"
            )
        return trimmed

    @field_validator("question_id")
    @classmethod
    def normalize_question_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip().lower().replace("_", "-")
        return trimmed or None

    @field_validator("question_params")
    @classmethod
    def normalize_question_params(
        cls, value: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        if value is None:
            return None
        cleaned: Dict[str, str] = {}
        for key, raw in value.items():
            text = str(raw or "").strip()
            if text:
                cleaned[str(key)] = text[:120]
        return cleaned or None

    @field_validator("findings")
    @classmethod
    def normalize_findings(
        cls, value: Optional[List[Dict[str, Any]]]
    ) -> Optional[List[Dict[str, Any]]]:
        if value is None:
            return None
        cleaned = [item for item in value if isinstance(item, dict)]
        if not cleaned:
            return None
        return cleaned[:MAX_FINDINGS_PER_REQUEST]

    @model_validator(mode="after")
    def resolve_payload(self) -> "AnalyzeCVEsRequest":
        findings = self.findings or []
        cve_ids = list(self.cve_ids or [])

        if findings:
            from_findings = _cve_ids_from_findings(findings)
            merged: List[str] = []
            seen: set[str] = set()
            for cve_id in from_findings + cve_ids:
                if cve_id not in seen:
                    seen.add(cve_id)
                    merged.append(cve_id)
            cve_ids = merged[:MAX_CVE_IDS_PER_REQUEST]

        if not cve_ids and not findings:
            raise ValueError("At least one CVE id or finding is required.")

        intent = self.intent
        mode = self.mode
        if intent is None and mode is None:
            intent = "insights"
            mode = "detail"
        elif intent is None and mode is not None:
            intent = _mode_to_intent(mode)
        elif intent is not None and mode is None:
            mode = _intent_to_mode(intent)

        assert intent is not None and mode is not None

        if intent == "ask_ai" and not (self.question or "").strip() and not self.question_id:
            raise ValueError(
                'A "question" or "question_id" is required when intent="ask_ai".'
            )

        self.intent = intent
        self.mode = _intent_to_mode(intent)
        self.cve_ids = cve_ids
        self.findings = findings or None
        return self


class RiskScoreDriver(BaseModel):
    driver: str
    score: int
    weight: float
    evidence: str


class RiskScoreResult(BaseModel):
    score: int
    rating: str
    confidence: str
    confidence_notes: List[str] = []
    drivers: List[RiskScoreDriver] = []
    method: Optional[str] = None


class AnalyzeCVEsResponse(BaseModel):
    status: str
    statusCode: Optional[int] = None
    invocation_source: Optional[str] = None
    reason: Optional[str] = None
    error: Optional[str] = None
    question: Optional[str] = None
    question_id: Optional[str] = None
    cve_ids_analyzed: List[str] = []
    total_valid_cve_ids: Optional[int] = None
    total_findings_provided: Optional[int] = None
    total_findings_analyzed: Optional[int] = None
    total_findings_skipped: Optional[int] = None
    findings_detailed: Optional[int] = None
    max_findings: Optional[int] = None
    signal_summary: Optional[Dict[str, Any]] = None
    ai_summary: Optional[str] = None
    # "prose" (one paragraph, no Markdown) or "sections" (### headings).
    ai_summary_format: Optional[str] = None
    # Computed by the Lambda from posture, not by the model — present on any
    # response that analyzed findings, regardless of intent.
    risk_score: Optional[RiskScoreResult] = None
    model_used: Optional[str] = None
    model_routing: Optional[Dict[str, Any]] = None
    mode: Optional[str] = None
    intent: Optional[str] = None


def _invoke_analyzer_lambda(payload: dict) -> dict:
    if not LAMBDA_FUNCTION_NAME:
        logger.error("CVE_ANALYZER_LAMBDA_NAME is not configured.")
        raise HTTPException(
            status_code=503,
            detail="Analysis service is not configured.",
        )

    try:
        response = _lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
    except (BotoCoreError, ClientError) as exc:
        logger.exception("Failed to invoke analyzer Lambda")
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach analysis service: {exc}",
        ) from exc

    raw = response.get("Payload")
    if raw is None:
        raise HTTPException(status_code=502, detail="Empty response from analysis service")

    try:
        body = raw.read()
        result = json.loads(body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        logger.exception("Analyzer Lambda returned invalid JSON")
        raise HTTPException(
            status_code=502,
            detail="Analysis service returned an invalid response",
        ) from exc

    # Function error (uncaught exception in Lambda)
    if response.get("FunctionError"):
        error_payload = result if isinstance(result, dict) else {}
        error_message = (
            error_payload.get("errorMessage")
            or error_payload.get("error")
            or error_payload.get("Message")
            or str(result)
        )
        error_type = str(error_payload.get("errorType") or "LambdaError")

        if error_type == "RuntimeError":
            raise HTTPException(
                status_code=503,
                detail="Analysis service is misconfigured. Please contact an administrator.",
            )
        if error_type in ("ValueError", "TypeError"):
            raise HTTPException(status_code=400, detail=error_message)

        raise HTTPException(
            status_code=502,
            detail=(
                f"The analysis service failed to process this request "
                f"({error_type}: {error_message})"
            ),
        )

    return result


@router.post("/api/cve-analysis", response_model=AnalyzeCVEsResponse)
async def analyze_cves(request: AnalyzeCVEsRequest) -> dict:
    """Relay findings (preferred) + cve_ids + intent/question to the analyzer Lambda."""
    payload: Dict[str, Any] = {
        "mode": request.mode,
        "intent": request.intent,
    }
    if request.cve_ids:
        payload["cve_ids"] = request.cve_ids
    if request.findings:
        payload["findings"] = request.findings
    if request.question:
        payload["question"] = request.question
    if request.question_id:
        payload["question_id"] = request.question_id
    if request.question_params:
        payload["question_params"] = request.question_params

    result = await to_thread(_invoke_analyzer_lambda, payload)

    if isinstance(result, dict) and str(result.get("status", "")).lower() == "error":
        message = result.get("error") or result.get("reason") or "Analysis failed"
        code = int(result.get("statusCode") or 400)
        if code >= 500:
            raise HTTPException(status_code=502, detail=str(message))
        raise HTTPException(status_code=400, detail=str(message))

    if isinstance(result, dict):
        if "mode" not in result:
            result = {**result, "mode": request.mode}
        if "intent" not in result:
            result = {**result, "intent": request.intent}
        if "ai_summary" in result:
            result = {**result, "ai_summary": _sanitize_ai_summary(result.get("ai_summary"))}
    return result
