"""
AI Risk Analyzer Lambda — Digital Footprint Dashboard.

Purpose:
  Analyze already-collected structured findings and generate analyst-friendly
  risk intelligence for a digital footprint dashboard.

Scope:
  - Does not perform scanning.
  - Does not perform vulnerability detection.
  - Does not enrich CVEs from external sources.
  - Only analyzes the CVEs/findings provided by the dashboard or backend.

Accepted request format:

  {
    "findings": [
      {
        "ip": "x.x.x.x",
        "cve_id": "CVE-2024-1234",
        "cvss": "9.8",
        "epss": "0.91",
        "kev": "true",
        "domains": "...",
        "hostnames": "...",
        "port": "443",
        "protocol": "tcp",
        "service_name": "https",
        "product": "Example Product",
        "version": "1.2.3",
        "summary": "Existing finding summary"
      }
    ],
    "cve_ids": ["CVE-2024-1234"],      # optional fallback when no findings
    "intent": "brief" | "analyze" | "remediate" | "next_steps",
    "mode":   "brief" | "detail"       # legacy alias; only used if intent is absent/invalid
  }

Analysis model:
  - Every valid finding in the request (up to MAX_INPUT_FINDINGS) is normalized
    and counted into an aggregate risk-posture summary.
  - Findings are ranked by KEV > EPSS > CVSS > verified. Only the top-ranked
    findings are sent to the model as full records; the posture summary carries
    the rest, so counts and trends always reflect the whole set even though the
    model only sees a sample.
  - "brief" is scoped to the top BRIEF_TOP_FINDINGS findings and uses the posture
    summary only to place them in the wider set. The other intents see up to
    MAX_DETAIL_FINDINGS.

Environment:
  BEDROCK_API_KEY           Required.
  BEDROCK_BASE_URL          Optional.
  BEDROCK_MODEL             Optional.
  BEDROCK_TIMEOUT_SECONDS   Optional (default 45).
  BEDROCK_MAX_RETRIES       Optional (default 1).

Dependency:
  openai
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from collections import Counter
from typing import Any

from openai import OpenAI, OpenAIError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BEDROCK_API_KEY = os.environ.get("BEDROCK_API_KEY", "")
BEDROCK_BASE_URL = os.environ.get(
    "BEDROCK_BASE_URL",
    "https://bedrock-runtime.us-west-2.amazonaws.com/openai/v1",
)
BEDROCK_MODEL = os.environ.get(
    "BEDROCK_MODEL",
    "openai.gpt-oss-120b-1:0",
)

def _env_number(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default

BEDROCK_TIMEOUT_SECONDS = _env_number("BEDROCK_TIMEOUT_SECONDS", 45.0)
BEDROCK_MAX_RETRIES = int(_env_number("BEDROCK_MAX_RETRIES", 1))

# Hard cap on how many records we will read out of a single request.
MAX_INPUT_FINDINGS = 500
# How many ranked findings are sent to the model as full records.
MAX_DETAIL_FINDINGS = 8
# The brief is scoped to the top critical findings rather than the wider set.
BRIEF_TOP_FINDINGS = 5
# Cap on bare CVE IDs echoed back / analyzed when no findings are supplied.
MAX_CVE_IDS = 25

# EPSS interpretation thresholds. Shared by the posture builder and the prompts
# so the model never describes a cut-off the code does not actually apply.
EPSS_NOTABLE = 0.5
EPSS_URGENT = 0.9

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)

INTENTS = ("brief", "analyze", "remediate", "next_steps")

_client: OpenAI | None = None

IP_FIELDS = ("primary_ip", "ip", "ip_address", "host_ip")
CVE_FIELDS = ("cve_id", "original_cve_id")

BOOL_FIELDS = frozenset({"kev", "verified"})

FINDING_FIELDS = (
    # Core identifiers
    "ip",
    "primary_ip",
    "ip_address",
    "host_ip",
    "cve_id",
    "original_cve_id",

    # Risk and exploitability signals
    "cvss",
    "cvss_v2",
    "cvss_version",
    "epss",
    "ranking_epss",
    "kev",
    "verified",

    # Asset and exposure context
    "domains",
    "hostnames",
    "org",
    "isp",
    "asn",
    "location_city",
    "location_country_code",

    # Service and technology context
    "port",
    "port_id",
    "protocol",
    "transport",
    "service_name",
    "service_confidence",
    "service_method",
    "product",
    "version",
    "os",
    "os_best_guess",
    "port_state",
    "port_state_reason",

    # Timing and source context
    "observed_at",
    "processed_at",
    "scan_started_at",
    "scan_completed_at",
    "scan_type",
    "source_file_name",

    # Existing pipeline summary
    "summary",
)

# Aliases are resolved into `cve_id` / `asset_ip`, so they are never copied into
# the normalized record. Everything else in the allow-list is copied verbatim.
ALIAS_FIELDS = frozenset(CVE_FIELDS + IP_FIELDS)
CONTEXT_FIELDS = frozenset(FINDING_FIELDS) - ALIAS_FIELDS

# ---------------------------------------------------------------------------
# Errors and client
# ---------------------------------------------------------------------------

class ModelError(RuntimeError):
    """Raised when the upstream model call fails or returns nothing usable."""

def _get_client() -> OpenAI:
    global _client

    if _client is None:
        if not BEDROCK_API_KEY:
            raise RuntimeError("BEDROCK_API_KEY is not configured")

        _client = OpenAI(
            api_key=BEDROCK_API_KEY,
            base_url=BEDROCK_BASE_URL,
            timeout=BEDROCK_TIMEOUT_SECONDS,
            max_retries=BEDROCK_MAX_RETRIES,
        )

    return _client

# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

_NULLISH = {"", "none", "null", "nan", "n/a", "na", "unknown", "-"}

def _safe_string(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (list, tuple, set)):
        parts = [p for p in (_safe_string(v) for v in value) if p]
        return ", ".join(dict.fromkeys(parts)) or None

    text = str(value).strip()

    if text.lower() in _NULLISH:
        return None

    return text

def _normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        return None

    if isinstance(value, str):
        lowered = value.strip().lower()

        if lowered in {"true", "yes", "y", "1", "kev", "known_exploited"}:
            return True

        if lowered in {"false", "no", "n", "0"}:
            return False

    return None

def _to_float(value: Any) -> float | None:
    """Best-effort numeric parse used for ranking and bucketing only."""
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()

    if not text or text.lower() in _NULLISH:
        return None

    percent = text.endswith("%")
    text = text.rstrip("%").strip()

    try:
        number = float(text)
    except ValueError:
        return None

    return number / 100.0 if percent else number

def _normalize_cve(value: Any) -> str | None:
    cve = _safe_string(value)

    if not cve:
        return None

    cve = cve.upper()

    if not CVE_RE.match(cve):
        return None

    return cve

def _normalize_cve_ids(raw: Any) -> list[str]:
    if raw is None:
        return []

    if not isinstance(raw, list):
        raise ValueError("cve_ids must be a list")

    out: list[str] = []
    seen: set[str] = set()

    for item in raw[:MAX_INPUT_FINDINGS]:
        cve = _normalize_cve(item)

        if not cve or cve in seen:
            continue

        seen.add(cve)
        out.append(cve)

        if len(out) >= MAX_CVE_IDS:
            break

    return out

def _normalize_finding_value(field: str, value: Any) -> Any:
    """
    Scores are deliberately kept as strings: it avoids Decimal/float
    serialization issues from DynamoDB, and the model only needs readable score
    context. Ranking and bucketing parse them with _to_float instead.
    """
    if field in BOOL_FIELDS:
        return _normalize_bool(value)

    return _safe_string(value)

def _pick_first(record: dict[str, Any], fields: tuple[str, ...]) -> str | None:
    for field in fields:
        value = _safe_string(record.get(field))
        if value:
            return value

    return None

def _pick_cve(record: dict[str, Any]) -> str | None:
    """First alias that holds a well-formed CVE ID, so a malformed `cve_id`
    can still fall back to `original_cve_id`."""
    for field in CVE_FIELDS:
        cve = _normalize_cve(record.get(field))
        if cve:
            return cve

    return None

def _normalize_findings(raw: Any) -> tuple[list[dict[str, Any]], int, int]:
    """
    Convert dashboard/backend records into a compact, AI-ready findings list.

    Returns (findings, provided_count, skipped_count).

    Only fields that support the risk-intelligence use case are kept. Raw JSON
    blobs and internal pipeline bookkeeping are intentionally excluded, and IP /
    CVE aliases are collapsed into a single field each so the prompt does not
    carry the same value three times.
    """
    if raw is None:
        return [], 0, 0

    if not isinstance(raw, list):
        raise ValueError("findings must be a list")

    provided = len(raw)
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    skipped = 0

    for item in raw[:MAX_INPUT_FINDINGS]:
        if not isinstance(item, dict):
            skipped += 1
            continue

        # Resolve identity first: a record without a usable CVE is dropped, so
        # there is no point normalizing the rest of its fields.
        primary_cve = _pick_cve(item)

        if not primary_cve:
            skipped += 1
            continue

        finding: dict[str, Any] = {}

        for field, value in item.items():
            if field not in CONTEXT_FIELDS:
                continue

            cleaned = _normalize_finding_value(field, value)

            if cleaned is None:
                continue

            finding[field] = cleaned

        finding["cve_id"] = primary_cve

        primary_ip = _pick_first(item, IP_FIELDS)

        if primary_ip:
            finding["asset_ip"] = primary_ip

        dedupe_key = "|".join(
            str(finding.get(key, ""))
            for key in (
                "cve_id",
                "asset_ip",
                "port",
                "port_id",
                "protocol",
                "service_name",
                "product",
                "version",
            )
        )

        if dedupe_key in seen:
            skipped += 1
            continue

        seen.add(dedupe_key)
        normalized.append(finding)

    if provided > MAX_INPUT_FINDINGS:
        skipped += provided - MAX_INPUT_FINDINGS

    return normalized, provided, skipped

# ---------------------------------------------------------------------------
# Ranking and aggregate posture
# ---------------------------------------------------------------------------

def _finding_epss(finding: dict[str, Any]) -> float | None:
    for field in ("epss", "ranking_epss"):
        value = _to_float(finding.get(field))
        if value is not None:
            return value

    return None

def _finding_cvss(finding: dict[str, Any]) -> float | None:
    for field in ("cvss", "cvss_v2"):
        value = _to_float(finding.get(field))
        if value is not None:
            return value

    return None

def _rank_key(finding: dict[str, Any]) -> tuple[int, float, float, int]:
    """KEV first, then exploit probability, then severity, then verified."""
    kev = 1 if finding.get("kev") is True else 0
    verified = 1 if finding.get("verified") is True else 0
    epss = _finding_epss(finding)
    cvss = _finding_cvss(finding)

    return (kev, epss if epss is not None else -1.0, cvss if cvss is not None else -1.0, verified)

def _severity_bucket(cvss: float | None) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"

def _top_counts(counter: Counter, limit: int = 5) -> list[dict[str, Any]]:
    return [
        {"value": value, "findings": count}
        for value, count in counter.most_common(limit)
    ]

def _build_posture(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate signals across ALL analyzed findings, not just the detailed ones."""
    severity = Counter()
    services = Counter()
    products = Counter()
    assets = Counter()
    cves: set[str] = set()
    kev_cves: list[str] = []

    kev_findings = 0
    verified_true = 0
    verified_false = 0
    epss_values: list[float] = []
    epss_high = 0

    for finding in findings:
        cve = finding.get("cve_id")
        if cve:
            cves.add(cve)

        cvss = _finding_cvss(finding)
        severity[_severity_bucket(cvss)] += 1

        if finding.get("kev") is True:
            kev_findings += 1
            if cve and cve not in kev_cves:
                kev_cves.append(cve)

        if finding.get("verified") is True:
            verified_true += 1
        elif finding.get("verified") is False:
            verified_false += 1

        epss = _finding_epss(finding)
        if epss is not None:
            epss_values.append(epss)
            if epss >= EPSS_NOTABLE:
                epss_high += 1

        asset = finding.get("asset_ip") or finding.get("hostnames") or finding.get("domains")
        if asset:
            assets[asset] += 1

        service = finding.get("service_name")
        port = finding.get("port") or finding.get("port_id")
        if service or port:
            services[f"{service or 'unknown-service'}/{port or 'unknown-port'}"] += 1

        product = finding.get("product")
        if product:
            version = finding.get("version")
            products[f"{product} {version}".strip() if version else product] += 1

    posture: dict[str, Any] = {
        "findings_analyzed": len(findings),
        "unique_cves": len(cves),
        "unique_assets": len(assets),
        "severity_breakdown": {
            bucket: severity.get(bucket, 0)
            for bucket in ("critical", "high", "medium", "low", "unknown")
        },
        "kev_findings": kev_findings,
        "kev_cves": kev_cves[:10],
        "epss_findings_scored": len(epss_values),
        "epss_at_or_above_0_5": epss_high,
        "max_epss": max(epss_values) if epss_values else None,
        "verified_true": verified_true,
        "verified_false": verified_false,
        "verified_unknown": len(findings) - verified_true - verified_false,
        "top_services": _top_counts(services),
        "top_products": _top_counts(products),
        "assets_with_most_findings": _top_counts(assets),
    }

    return posture

# ---------------------------------------------------------------------------
# Output sanitizing
# ---------------------------------------------------------------------------

# gpt-oss models are trained on the harmony format and can leak channel markers
# or reasoning text into `content` (e.g. "<|channel|>analysis<|message|>...",
# "<think>...</think>", or a bare "analysis" prefix). Prompting alone does not
# reliably stop this, so the response is cleaned before it reaches the dashboard.

_HARMONY_FINAL_RE = re.compile(r"<\|channel\|>\s*final\s*<\|message\|>", re.I)
_HARMONY_TOKEN_RE = re.compile(r"<\|[^|]*\|>")
_REASON_BLOCK_RE = re.compile(
    r"<\s*(think|thinking|reasoning|analysis|scratchpad)\b[^>]*>.*?<\s*/\s*\1\s*>",
    re.I | re.S,
)
_REASON_TAG_RE = re.compile(
    r"<\s*/?\s*(think|thinking|reasoning|analysis|scratchpad|final|commentary)\b[^>]*>",
    re.I,
)
_FENCE_RE = re.compile(r"\A\s*```[A-Za-z]*\s*\n(.*?)\n?\s*```\s*\Z", re.S)
_HEADING_RE = re.compile(r"^#{1,4}\s+\S", re.M)
_LEAD_CHANNEL_RE = re.compile(r"\A(assistant)?\s*(analysis|commentary|final)\b[:.\s]*", re.I)
_BLANK_LINES_RE = re.compile(r"\n{3,}")
_TRAILING_SPACE_RE = re.compile(r"[ \t]+$", re.M)

def _sanitize_output(text: str) -> str:
    """
    Strip reasoning leakage, channel markers, and wrapper noise from model output.

    The prompts require the response to begin with a Markdown heading and forbid
    preamble, so anything before the first heading is treated as leaked scaffolding.
    """
    if not text:
        return ""

    # If a harmony final channel is present, everything before it is scaffolding.
    finals = list(_HARMONY_FINAL_RE.finditer(text))
    if finals:
        text = text[finals[-1].end():]

    text = _REASON_BLOCK_RE.sub("", text)
    text = _HARMONY_TOKEN_RE.sub("", text)
    text = _REASON_TAG_RE.sub("", text)

    fenced = _FENCE_RE.match(text)
    if fenced:
        text = fenced.group(1)

    heading = _HEADING_RE.search(text)
    if heading and heading.start() > 0:
        text = text[heading.start():]

    text = _LEAD_CHANNEL_RE.sub("", text.lstrip())
    text = _TRAILING_SPACE_RE.sub("", text)
    text = _BLANK_LINES_RE.sub("\n\n", text)

    return text.strip()

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

BASE_SYSTEM_PROMPT = f"""
You are a cybersecurity analyst supporting a digital footprint dashboard. You analyze
already-collected structured findings and return risk intelligence.

Grounding:
- Use only the request data. Never scan, enrich, or draw on outside knowledge.
- Never invent assets, exploit activity, business impact, ownership, or remediation status.
- Every number you state must come from `posture_summary` or `top_findings`.
- Name a missing field as unknown once. Do not hedge every sentence.

Data:
- `posture_summary` covers ALL analyzed findings and is the source of truth for counts
  and trends. `top_findings` is the highest-risk sample, ranked KEV > EPSS > CVSS >
  verified. When `findings_analyzed` exceeds the records in `top_findings`, describe the
  population from `posture_summary` and use `top_findings` only as examples.
- `kev` true = CVE is known to be exploited; the strongest single signal.
- `epss` / `ranking_epss` = exploit probability (0-1). >={EPSS_NOTABLE} is notable,
  >={EPSS_URGENT} is urgent.
- `cvss` / `cvss_v2` = severity, not likelihood. `verified` = the pipeline confirmed the finding.
- `asset_ip`, `domains`, `hostnames` = asset identity. `port`, `protocol`, `service_name`,
  `product`, `version` = exposed service.
- `summary` = context written earlier in the pipeline; input only, not a source of new facts.

Output:
- Return only the finished answer. No reasoning, planning, drafts, preamble, or meta
  commentary. No channel markers, analysis tags, or XML-style tags.
- Begin with the first required heading. Use exactly the headings given, in the order
  given, and no others. No code fences.
- Plain Markdown only: headings, short paragraphs, single-line bullets. No tables, nested
  bullets, or numbered lists.
- Bold only risk signals and labels: **KEV**, **CVSS 9.8**, **EPSS 0.94**.
- State each fact once. Never restate a point in a later section.
- Use concrete detail - counts, CVE IDs, assets, services, products - instead of adjectives.
- No filler openers such as "It is important to note", and no closing summary.
""".strip()


# Each entry: (intent-specific instructions, max_tokens).
#
# max_tokens is a ceiling, not a target: gpt-oss reasoning tokens are drawn from
# the same budget, so the cap must cover reasoning + answer. Length is controlled
# by the prompt, not by the cap. An over-tight cap surfaces as an empty `content`
# with populated `reasoning_content`, which _generate reports as a ModelError.
_INTENT_PROMPTS: dict[str, tuple[str, int]] = {
    "brief": (
        f"""
Write a risk brief on the highest-risk findings in `top_findings` (up to
{BRIEF_TOP_FINDINGS}, fewer if fewer were provided). Those findings are the entire
subject of this brief. Use `posture_summary` only to place them in the wider set: how
many findings and assets exist in total, and whether these are outliers or typical.
Do not summarize the wider set for its own sake.

Write prose. Do not enumerate or step through the findings one by one, and use no
bullets anywhere. Total length: 120-170 words.

### Risk Posture
One paragraph, 3-5 sentences. What these findings show as a group: the assets and
services they sit on, where their severity sits, how many are known-exploited or highly
exploitable, and how many are confirmed. Give the total findings and assets so the
reader knows what share of the environment this represents. Say whether they cluster on
one asset, product, or exposed service, or are spread across unrelated systems, and what
that shape means.

### What Stands Out
One paragraph, 2-3 sentences. Which one or two findings drive the risk, and why. Name
the CVE, asset, service, or product that is the reason. If they are broadly equivalent,
say so rather than inventing a hierarchy.

### Priority Action
One sentence. The single next thing the analyst should do.

If the data is too thin for a confident read, say so once in Risk Posture and name the
missing context.
""",
        900,
    ),
    "analyze": (
        """
Write an analyst risk analysis. Total length: under 300 words.

### Summary
One paragraph, 2-4 sentences on the risk picture across the analyzed set, grounded in
the posture counts.

### Top Risks
3-5 single-line bullets, highest first. Each: the affected asset or service and the CVE,
then the signals that rank it. Collapse the same CVE across multiple assets into one
bullet with a count.

### Why It Matters
2-3 sentences on plausible security impact, tied only to the services and products
present in the data.

### Confidence and Gaps
1-3 single-line bullets on missing fields, unverified findings, or sampling that limit
confidence.
""",
        900,
    ),
    "remediate": (
        """
Write remediation guidance. Total length: under 300 words.

### Priority Order
2-4 single-line bullets, ordered. Each: what to fix, and the signal that puts it at that
rank.

### Recommended Actions
3-5 single-line bullets. Concrete steps only: patch or upgrade a named product and
version, close or restrict an exposed port, review a configuration, segment, or validate.
Tie each action to the finding it addresses.

### Validation
2-3 single-line bullets on confirming the fix, framed as re-checking the provided
finding, exposure, or version.

### Limitations
1-3 single-line bullets on missing data that blocks more specific guidance.

Rules:
- Never name a vendor patch, version, or advisory that is not in the data.
- If product or version is missing, the first action is confirming the affected software.
- Never state that remediation is complete unless the data says so.
""",
        900,
    ),
    "next_steps": (
        """
Write an ordered action plan. Total length: under 250 words.

### Immediate
2-3 single-line bullets on what to act on today, highest-signal first.

### This Week
2-3 single-line bullets on follow-up work to schedule.

### Owners
2-3 single-line bullets mapping the actions above to owner groups: vulnerability
management, IT operations, network or security engineering, application owners, or
dashboard/data owners.

### Data Needed
1-3 single-line bullets on missing fields that would improve triage.

Rules:
- Do not recommend broad new scanning. Frame validation as confirming a provided finding,
  exposure, version, or remediation status.
- No unrelated program or project work.
""",
        800,
    ),
}

# Composed system prompt per intent: shared rules once, then the intent contract.
PROMPTS: dict[str, tuple[str, int]] = {
    intent: (f"{BASE_SYSTEM_PROMPT}\n\n{instructions.strip()}", max_tokens)
    for intent, (instructions, max_tokens) in _INTENT_PROMPTS.items()
}


# Headings each intent must produce. Used to reject output that ignored the
# format entirely (usually leaked reasoning with no answer attached).
REQUIRED_HEADINGS: dict[str, tuple[str, ...]] = {
    "brief": ("Risk Posture", "What Stands Out", "Priority Action"),
    "analyze": ("Summary", "Top Risks", "Why It Matters", "Confidence and Gaps"),
    "remediate": ("Priority Order", "Recommended Actions", "Validation", "Limitations"),
    "next_steps": ("Immediate", "This Week", "Owners", "Data Needed"),
}

# A well-formed answer carries every heading; require a majority so a single
# dropped or reworded heading does not fail an otherwise usable response.
MIN_REQUIRED_HEADINGS = 2

_HEADING_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    intent: tuple(
        re.compile(rf"^#{{1,4}}\s*{re.escape(heading)}\b", re.I | re.M)
        for heading in headings
    )
    for intent, headings in REQUIRED_HEADINGS.items()
}


def _validate_prompts() -> None:
    """Fail fast at import if the prompts and the validator drift apart."""
    for intent in INTENTS:
        if intent not in PROMPTS:
            raise RuntimeError(f"missing prompt for intent {intent}")

        if intent not in REQUIRED_HEADINGS:
            raise RuntimeError(f"missing headings for intent {intent}")

        if len(REQUIRED_HEADINGS[intent]) < MIN_REQUIRED_HEADINGS:
            raise RuntimeError(
                f"intent {intent} declares fewer headings than the validator requires"
            )

        for heading in REQUIRED_HEADINGS[intent]:
            if f"### {heading}" not in PROMPTS[intent][0]:
                raise RuntimeError(
                    f"heading '{heading}' is not in the {intent} prompt"
                )


_validate_prompts()


def _detail_limit(intent: str) -> int:
    """How many ranked findings this intent sees as full records."""
    return BRIEF_TOP_FINDINGS if intent == "brief" else MAX_DETAIL_FINDINGS


def _has_required_heading(text: str, intent: str) -> bool:
    """
    True when the output carries at least MIN_REQUIRED_HEADINGS of the intent's
    headings as actual Markdown headings. Matching on heading lines rather than
    bare substrings stops common words ("summary", "immediate") in leaked
    reasoning from passing as a formatted answer.
    """
    matched = sum(
        1 for pattern in _HEADING_PATTERNS[intent] if pattern.search(text)
    )

    return matched >= MIN_REQUIRED_HEADINGS


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

def _resolve_intent_mode(body: dict[str, Any]) -> tuple[str, str]:
    """
    `intent` is authoritative. `mode` is a legacy alias kept for older dashboard
    callers and is only consulted when `intent` is missing or invalid.
    """
    intent = str(body.get("intent") or "").strip().lower()
    mode = str(body.get("mode") or "").strip().lower()

    if intent not in INTENTS:
        intent = "brief" if mode == "brief" else "analyze"

    return intent, ("brief" if intent == "brief" else "detail")

def _build_context(
    cve_ids: list[str],
    findings: list[dict[str, Any]],
    posture: dict[str, Any] | None,
    detail_limit: int,
) -> str:
    if not findings:
        return (
            "No structured findings were provided. Only CVE IDs are available:\n"
            + "\n".join(f"- {cve_id}" for cve_id in cve_ids)
            + "\n\nNo asset, severity, KEV, EPSS, exposure, product, version, or "
            "remediation context was provided. State once that the assessment is "
            "limited to identifiers, then name the context required to go further."
        )

    detailed = findings[:detail_limit]
    omitted = len(findings) - len(detailed)

    sections = [
        "posture_summary (aggregated over ALL analyzed findings):",
        json.dumps(posture, indent=2, sort_keys=True),
        "",
        f"top_findings (highest-risk {len(detailed)} of {len(findings)} analyzed findings):",
        json.dumps(detailed, indent=2, sort_keys=True),
    ]

    if omitted:
        sections.append(
            f"\n{omitted} further analyzed findings are not shown individually. "
            "Use posture_summary for anything covering the full set."
        )

    return "\n".join(sections)

def _generate(
    intent: str,
    cve_ids: list[str],
    findings: list[dict[str, Any]],
    posture: dict[str, Any] | None,
) -> str:
    system_prompt, max_tokens = PROMPTS[intent]

    user_prompt = (
        f'Produce the "{intent}" output for the data below.\n\n'
        f"{_build_context(cve_ids, findings, posture, _detail_limit(intent))}\n\n"
        "Use only this data. Follow the required headings and length limit exactly."
    )

    client = _get_client()

    try:
        completion = client.chat.completions.create(
            model=BEDROCK_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
    except OpenAIError as exc:
        logger.exception("Model request failed")
        raise ModelError(f"Model request failed: {exc}") from exc

    if not completion.choices:
        raise ModelError("Model returned no choices")

    choice = completion.choices[0]
    message = getattr(choice, "message", None)
    raw = (getattr(message, "content", None) or "").strip()
    finish_reason = getattr(choice, "finish_reason", None)

    if not raw:
        # Some reasoning models return the chain of thought in a separate field
        # and leave `content` empty when the token budget is exhausted.
        if getattr(message, "reasoning_content", None):
            raise ModelError(
                "Model returned reasoning without a final answer; "
                "raise the token limit for this intent."
            )
        raise ModelError("Model returned an empty summary")

    text = _sanitize_output(raw)

    if not text:
        logger.warning("Model output was entirely scaffolding for intent=%s", intent)
        raise ModelError("Model returned no usable summary")

    if not _has_required_heading(text, intent):
        logger.warning(
            "Model ignored the required format for intent=%s (raw=%r)", intent, raw[:300]
        )
        raise ModelError("Model returned a malformed summary")

    if finish_reason == "length":
        logger.warning("Model output truncated for intent=%s", intent)
        text += "\n\n_Output truncated at the token limit._"

    return text

def _is_http_event(event: dict[str, Any]) -> bool:
    """True for API Gateway REST/HTTP and Lambda Function URL invocations."""
    return isinstance(event, dict) and (
        "httpMethod" in event or "requestContext" in event or "rawPath" in event
    )

def _parse_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    if "cve_ids" in event or "findings" in event:
        return event

    body = event.get("body")

    if isinstance(body, dict):
        return body

    if isinstance(body, str):
        if event.get("isBase64Encoded"):
            try:
                body = base64.b64decode(body).decode("utf-8")
            except Exception as exc:
                raise ValueError("Request body could not be base64-decoded") from exc

        try:
            parsed = json.loads(body or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON") from exc

        if not isinstance(parsed, dict):
            raise ValueError("Request body must be a JSON object")

        return parsed

    if body is None and _is_http_event(event):
        raise ValueError("Request body is required")

    return event

def _wrap(payload: dict[str, Any], http: bool) -> dict[str, Any]:
    if not http:
        return payload

    return {
        "statusCode": payload.get("statusCode", 200),
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }

def _error_response(message: str, status_code: int = 400) -> dict[str, Any]:
    return {
        "status": "error",
        "statusCode": status_code,
        "error": message,
    }

def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    event = event or {}
    http = _is_http_event(event)

    try:
        body = _parse_event(event)

        cve_ids = _normalize_cve_ids(body.get("cve_ids"))
        findings, provided, skipped = _normalize_findings(body.get("findings"))

        posture: dict[str, Any] | None = None

        if findings:
            findings.sort(key=_rank_key, reverse=True)
            posture = _build_posture(findings)

            merged: list[str] = []
            seen: set[str] = set()

            for cve_id in [f["cve_id"] for f in findings] + cve_ids:
                if cve_id not in seen:
                    seen.add(cve_id)
                    merged.append(cve_id)

            cve_ids = merged[:MAX_CVE_IDS]

        if not cve_ids and not findings:
            raise ValueError(
                "At least one valid CVE ID or structured finding is required."
            )

        intent, mode = _resolve_intent_mode(body)
        summary = _generate(intent, cve_ids, findings, posture)

        return _wrap(
            {
                "status": "ok",
                "statusCode": 200,
                "invocation_source": "dashboard",
                "intent": intent,
                "mode": mode,
                "ai_summary": summary,
                "cve_ids_analyzed": cve_ids,
                "total_valid_cve_ids": len(cve_ids),
                "total_findings_provided": provided,
                "total_findings_analyzed": len(findings),
                "total_findings_skipped": skipped,
                "findings_detailed": min(len(findings), _detail_limit(intent)),
                "max_findings": _detail_limit(intent),
                "signal_summary": posture,
            },
            http,
        )

    except ValueError as exc:
        return _wrap(_error_response(str(exc), status_code=400), http)

    except ModelError as exc:
        return _wrap(_error_response(str(exc), status_code=502), http)

    except RuntimeError as exc:
        return _wrap(_error_response(str(exc), status_code=500), http)

    except Exception:
        logger.exception("Unexpected Lambda error")
        return _wrap(
            _error_response(
                "Unexpected error while generating risk intelligence.",
                status_code=500,
            ),
            http,
        )
