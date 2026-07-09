"""
Optimized NVD CVE -> S3 pipeline exposed through FastAPI.

Endpoints:
    POST /cves/sync
    POST /cves/sync-from-list
    POST /cves/sync-from-dynamodb
    GET  /cves/latest
    GET  /cves/latest-raw
    GET  /health

This version keeps the original design but tightens the unsafe areas:
    - validates CVE IDs, severity, date-pair filters, and record limits before calling NVD
    - converts non-retryable NVD/httpx failures into clean HTTPException responses
    - uses an async rate limiter for specific-CVE lookups so requests can overlap safely
    - avoids blocking the FastAPI event loop with boto3/pandas/pyarrow work
    - uses unique run stems instead of repeated S3 HEAD checks, avoiding race conditions
    - publishes the flat JSONL file last so /cves/latest does not expose incomplete runs
    - scans DynamoDB with a projection so it does not pull entire items unnecessarily
    - recursively extracts CPE matches from nested NVD configuration nodes
"""

import asyncio
import io
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import boto3
import httpx
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nvd-cve-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME")
DYNAMODB_CVE_ID_ATTRIBUTE = os.getenv("DYNAMODB_CVE_ID_ATTRIBUTE", "cve_id")
DYNAMODB_STATUS_ATTRIBUTE = os.getenv("DYNAMODB_STATUS_ATTRIBUTE")

CVE_LIST_S3_KEY = os.getenv("CVE_LIST_S3_KEY", "cves/cve_watchlist.json")

RAW_PREFIX = "cves/raw/"
FLAT_PREFIX = "cves/flat/"

BASENAME_SYNC = "cves"
BASENAME_LIST = "cves_list"
BASENAME_DYNAMO = "cves_db"

NVD_MAX_RESULTS_PER_PAGE = 2000
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

if not S3_BUCKET_NAME:
    logger.warning("S3_BUCKET_NAME is not set; S3-backed endpoints will fail until configured.")

# boto3 uses environment credentials, IAM role credentials, or shared credentials.
s3_client = boto3.client("s3", region_name=AWS_REGION)
dynamodb_resource = boto3.resource("dynamodb", region_name=AWS_REGION)

app = FastAPI(title="NVD CVE Sync Service")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SyncResult(BaseModel):
    s3_key: str
    jsonl_key: str
    parquet_key: str
    total_results: int
    results_fetched: int
    synced_at: str


class DynamoSyncResult(BaseModel):
    s3_key: str
    jsonl_key: str
    parquet_key: str
    requested: int
    results_fetched: int
    not_found: List[str]
    error_count: int = 0
    synced_at: str


class ListSyncResult(BaseModel):
    s3_key: str
    jsonl_key: str
    parquet_key: str
    source_key: str
    requested: int
    results_fetched: int
    not_found: List[str]
    error_count: int = 0
    synced_at: str


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def require_s3_bucket() -> str:
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3_BUCKET_NAME is not configured on the server.")
    return S3_BUCKET_NAME


def normalize_cve_id(value: Any) -> Optional[str]:
    """Normalize a single CVE ID. Returns None for blank values."""
    if value is None:
        return None
    cve_id = str(value).strip().upper()
    if not cve_id:
        return None
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=422, detail=f"Invalid CVE ID format: {value!r}")
    return cve_id


def normalize_cve_ids(values: Iterable[Any]) -> List[str]:
    """Normalize and de-duplicate CVE IDs while preserving input order."""
    seen = set()
    deduped: List[str] = []
    for value in values:
        cve_id = normalize_cve_id(value)
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            deduped.append(cve_id)
    return deduped


def validate_severity(severity: Optional[str]) -> Optional[str]:
    if severity is None:
        return None
    normalized = severity.strip().upper()
    if normalized not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity {severity!r}. Use one of: {', '.join(sorted(VALID_SEVERITIES))}.",
        )
    return normalized


def validate_pub_date_pair(pub_start_date: Optional[str], pub_end_date: Optional[str]) -> None:
    if bool(pub_start_date) != bool(pub_end_date):
        raise HTTPException(
            status_code=422,
            detail="pub_start_date and pub_end_date must be provided together.",
        )


def validate_positive_int(value: Optional[int], name: str) -> Optional[int]:
    if value is not None and value <= 0:
        raise HTTPException(status_code=422, detail=f"{name} must be greater than 0.")
    return value


# ---------------------------------------------------------------------------
# NVD fetch logic
# ---------------------------------------------------------------------------

async def _nvd_get(
    client: httpx.AsyncClient,
    params: Dict[str, Any],
    headers: Dict[str, str],
    max_attempts: int = 4,
) -> Dict[str, Any]:
    """Perform one NVD GET with retry/backoff and consistent error conversion."""
    backoff = 2.0

    for attempt in range(1, max_attempts + 1):
        try:
            resp = await client.get(NVD_BASE_URL, params=params, headers=headers)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            if attempt == max_attempts:
                raise HTTPException(status_code=504, detail=f"NVD request failed after retries: {exc}") from exc
            logger.warning("NVD transport error (%s); retrying in %.1fs", exc, backoff)
            await asyncio.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 403:
            raise HTTPException(
                status_code=502,
                detail="NVD rejected the request with 403. Check NVD_API_KEY and NVD access limits.",
            )

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == max_attempts:
                raise HTTPException(
                    status_code=502,
                    detail=f"NVD returned {resp.status_code} after {max_attempts} attempts.",
                )
            retry_after = resp.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else backoff
            except ValueError:
                wait = backoff
            logger.warning("NVD returned %s; retrying in %.1fs", resp.status_code, wait)
            await asyncio.sleep(wait)
            backoff *= 2
            continue

        if resp.is_error:
            detail = resp.text[:500] if resp.text else resp.reason_phrase
            raise HTTPException(status_code=502, detail=f"NVD returned {resp.status_code}: {detail}")

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=502, detail=f"NVD returned invalid JSON: {exc}") from exc

    raise HTTPException(status_code=502, detail="NVD request failed.")


async def fetch_cves(
    keyword_search: Optional[str] = None,
    cve_id: Optional[str] = None,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
    severity: Optional[str] = None,
    results_per_page: int = NVD_MAX_RESULTS_PER_PAGE,
    max_records: Optional[int] = None,
) -> Dict[str, Any]:
    """Fetch CVE records from NVD, paginating as needed."""
    validate_pub_date_pair(pub_start_date, pub_end_date)
    severity = validate_severity(severity)
    max_records = validate_positive_int(max_records, "max_records")
    normalized_cve_id = normalize_cve_id(cve_id) if cve_id else None

    if results_per_page <= 0 or results_per_page > NVD_MAX_RESULTS_PER_PAGE:
        raise HTTPException(
            status_code=422,
            detail=f"results_per_page must be between 1 and {NVD_MAX_RESULTS_PER_PAGE}.",
        )

    if max_records is not None:
        results_per_page = min(results_per_page, max_records)

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params: Dict[str, Any] = {"resultsPerPage": results_per_page, "startIndex": 0}

    if keyword_search:
        params["keywordSearch"] = keyword_search.strip()
    if normalized_cve_id:
        params["cveId"] = normalized_cve_id
    if pub_start_date and pub_end_date:
        params["pubStartDate"] = pub_start_date
        params["pubEndDate"] = pub_end_date
    if severity:
        params["cvssV3Severity"] = severity

    all_vulnerabilities: List[Dict[str, Any]] = []
    total_results = 0

    async with httpx.AsyncClient(timeout=60.0) as client:
        while True:
            data = await _nvd_get(client, params, headers)
            total_results = int(data.get("totalResults") or 0)
            vulns = data.get("vulnerabilities") or []

            if not isinstance(vulns, list):
                raise HTTPException(status_code=502, detail="NVD response shape was unexpected: vulnerabilities is not a list.")

            all_vulnerabilities.extend(vulns)
            fetched_so_far = len(all_vulnerabilities)
            logger.info("Fetched %s/%s CVEs", fetched_so_far, total_results)

            if max_records is not None and fetched_so_far >= max_records:
                all_vulnerabilities = all_vulnerabilities[:max_records]
                break

            if not vulns:
                break

            next_index = int(params["startIndex"]) + results_per_page
            if next_index >= total_results:
                break
            params["startIndex"] = next_index

    return {
        "totalResults": total_results,
        "resultsFetched": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }


class AsyncRateLimiter:
    """Simple start-time limiter for async tasks sharing one external API limit."""

    def __init__(self, interval_seconds: float):
        self.interval_seconds = interval_seconds
        self._lock = asyncio.Lock()
        self._next_available = 0.0

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            if now < self._next_available:
                await asyncio.sleep(self._next_available - now)
                now = loop.time()
            self._next_available = max(now, self._next_available) + self.interval_seconds


async def fetch_specific_cves(cve_ids: Sequence[str], max_workers: Optional[int] = None) -> Dict[str, Any]:
    """
    Fetch specific CVEs from NVD.

    The original code slept after each completed request. This version spaces
    request starts instead, allowing response time to overlap without knowingly
    exceeding the configured API pacing.
    """
    normalized_ids = normalize_cve_ids(cve_ids)
    if not normalized_ids:
        return {
            "requested": 0,
            "resultsFetched": 0,
            "notFound": [],
            "errors": [],
            "vulnerabilities": [],
            "fetchedAt": datetime.now(timezone.utc).isoformat(),
        }

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    interval_seconds = 0.65 if NVD_API_KEY else 6.1
    max_workers = max_workers or (8 if NVD_API_KEY else 2)
    limiter = AsyncRateLimiter(interval_seconds)
    semaphore = asyncio.Semaphore(max_workers)

    async def lookup_one(index: int, cve_id: str, client: httpx.AsyncClient) -> Tuple[int, str, List[Dict[str, Any]], Optional[str]]:
        async with semaphore:
            await limiter.wait()
            try:
                data = await _nvd_get(client, {"cveId": cve_id}, headers)
                vulns = data.get("vulnerabilities") or []
                if not isinstance(vulns, list):
                    return index, cve_id, [], "NVD response shape was unexpected."
                return index, cve_id, vulns, None
            except HTTPException:
                raise
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                return index, cve_id, [], str(exc)

    lookup_results: List[Tuple[int, str, List[Dict[str, Any]], Optional[str]]] = []
    async with httpx.AsyncClient(timeout=60.0) as client:
        tasks = [asyncio.create_task(lookup_one(i, cid, client)) for i, cid in enumerate(normalized_ids)]
        try:
            for completed in asyncio.as_completed(tasks):
                lookup_results.append(await completed)
                logger.info("Checked %s/%s CVEs", len(lookup_results), len(normalized_ids))
        except HTTPException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    lookup_results.sort(key=lambda item: item[0])

    found: List[Dict[str, Any]] = []
    not_found: List[str] = []
    errors: List[Dict[str, str]] = []

    for _, cve_id, vulns, error in lookup_results:
        if error:
            logger.warning("NVD lookup failed for %s: %s", cve_id, error)
            errors.append({"cve_id": cve_id, "error": error})
        elif vulns:
            found.extend(vulns)
        else:
            not_found.append(cve_id)

    return {
        "requested": len(normalized_ids),
        "resultsFetched": len(found),
        "notFound": not_found,
        "errors": errors,
        "vulnerabilities": found,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Flattening logic
# ---------------------------------------------------------------------------

_LIST_SEP = "; "
MAX_LIST_ITEMS = 10

CVSS_PREFERENCE = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]

CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other", "unknown", "UNKNOWN"}


def _join_unique(values: Iterable[Any]) -> Optional[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return _LIST_SEP.join(out) if out else None


def _join_capped(values: Iterable[Any], limit: int = MAX_LIST_ITEMS) -> Optional[str]:
    seen = set()
    unique: List[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            unique.append(text)
    if not unique:
        return None
    if len(unique) <= limit:
        return _LIST_SEP.join(unique)
    return _LIST_SEP.join(unique[:limit]) + f" (+{len(unique) - limit} more)"


def _first_english_description(descriptions: Sequence[Dict[str, Any]]) -> Optional[str]:
    for desc in descriptions or []:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    for desc in descriptions or []:
        if desc.get("value"):
            return desc["value"]
    return None


def _extract_cvss_metric(metrics: Dict[str, Any], key: str) -> Dict[str, Any]:
    entries = (metrics or {}).get(key, [])
    if not entries:
        return {}

    primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
    cvss_data = primary.get("cvssData") or {}

    return {
        "base_score": cvss_data.get("baseScore"),
        "severity": primary.get("baseSeverity") or cvss_data.get("baseSeverity"),
        "exploitability_score": primary.get("exploitabilityScore"),
        "impact_score": primary.get("impactScore"),
        "attack_vector": cvss_data.get("attackVector") or cvss_data.get("accessVector"),
        "attack_complexity": cvss_data.get("attackComplexity") or cvss_data.get("accessComplexity"),
        "privileges_required": cvss_data.get("privilegesRequired"),
        "user_interaction": cvss_data.get("userInteraction"),
    }


def _resolve_primary_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    for key, version in CVSS_PREFERENCE:
        metric = _extract_cvss_metric(metrics, key)
        if metric.get("base_score") is not None:
            return {"cvss_version": version, **metric}
    return {
        "cvss_version": None,
        "base_score": None,
        "severity": None,
        "exploitability_score": None,
        "impact_score": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
    }


def _has_reference_tag(references: Sequence[Dict[str, Any]], tag: str) -> bool:
    return any(tag in (ref.get("tags") or []) for ref in references or [])


def _extract_cwe_ids(weaknesses: Sequence[Dict[str, Any]]) -> List[str]:
    cwe_ids: List[str] = []
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value")
            if desc.get("lang") == "en" and value and value not in CWE_PLACEHOLDERS:
                cwe_ids.append(value)
    return cwe_ids


def _extract_cpe_criteria_from_node(node: Dict[str, Any]) -> List[str]:
    criteria: List[str] = []
    for match in node.get("cpeMatch", []) or []:
        value = match.get("criteria")
        if value:
            criteria.append(value)
    for child in node.get("children", []) or []:
        criteria.extend(_extract_cpe_criteria_from_node(child))
    return criteria


def _extract_cpe_criteria(configurations: Sequence[Dict[str, Any]]) -> List[str]:
    criteria: List[str] = []
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            criteria.extend(_extract_cpe_criteria_from_node(node))
    return criteria


def _extract_vendors_and_products(cpe_criteria: Sequence[str]) -> Tuple[List[str], List[str]]:
    vendors: List[str] = []
    products: List[str] = []
    for criteria in cpe_criteria:
        parts = criteria.split(":")
        if len(parts) >= 5:
            vendors.append(parts[3])
            products.append(parts[4])
    return vendors, products


def flatten_vulnerability(vuln: Dict[str, Any], fetched_at: Optional[str] = None) -> Dict[str, Any]:
    cve = vuln.get("cve") or {}
    cvss = _resolve_primary_cvss(cve.get("metrics") or {})
    references = cve.get("references") or []
    cpe_criteria = _extract_cpe_criteria(cve.get("configurations") or [])
    vendors, products = _extract_vendors_and_products(cpe_criteria)

    return {
        "cve_id": cve.get("id"),
        "description": _first_english_description(cve.get("descriptions") or []),
        "cwe_ids": _join_unique(_extract_cwe_ids(cve.get("weaknesses") or [])),
        "cvss_version": cvss["cvss_version"],
        "base_score": cvss["base_score"],
        "severity": cvss["severity"],
        "impact_score": cvss["impact_score"],
        "exploitability_score": cvss["exploitability_score"],
        "attack_vector": cvss["attack_vector"],
        "attack_complexity": cvss["attack_complexity"],
        "privileges_required": cvss["privileges_required"],
        "user_interaction": cvss["user_interaction"],
        "has_patch": _has_reference_tag(references, "Patch"),
        "has_exploit": _has_reference_tag(references, "Exploit"),
        "vendors": _join_capped(vendors),
        "products": _join_capped(products),
        "affected_product_count": len(set(cpe_criteria)),
        "vuln_status": cve.get("vulnStatus"),
        "reference_count": len(references),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "fetched_at": fetched_at,
    }


def flatten_result(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    fetched_at = result.get("fetchedAt")
    return [flatten_vulnerability(vuln, fetched_at=fetched_at) for vuln in result.get("vulnerabilities", []) or []]


FLAT_CVE_COLUMNS = [
    "cve_id", "description", "cwe_ids",
    "cvss_version", "base_score", "severity", "impact_score",
    "exploitability_score", "attack_vector", "attack_complexity",
    "privileges_required", "user_interaction",
    "has_patch", "has_exploit",
    "vendors", "products", "affected_product_count",
    "vuln_status", "reference_count",
    "published", "last_modified", "fetched_at",
]

TIMESTAMP_COLUMNS = ["published", "last_modified", "fetched_at"]
FLOAT_COLUMNS = ["base_score", "impact_score", "exploitability_score"]
INT_COLUMNS = ["affected_product_count", "reference_count"]
BOOL_COLUMNS = ["has_patch", "has_exploit"]
STRING_COLUMNS = [
    column for column in FLAT_CVE_COLUMNS
    if column not in TIMESTAMP_COLUMNS + FLOAT_COLUMNS + INT_COLUMNS + BOOL_COLUMNS
]


# ---------------------------------------------------------------------------
# CVE list helpers
# ---------------------------------------------------------------------------

def _extract_cve_ids_from_loaded_json(raw: Any) -> List[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and "cve_ids" in raw:
        cve_ids = raw["cve_ids"]
        if not isinstance(cve_ids, list):
            raise HTTPException(status_code=422, detail="The 'cve_ids' field must be a list.")
        return cve_ids
    if isinstance(raw, dict) and "cve_id" in raw:
        return [raw["cve_id"]]
    raise HTTPException(
        status_code=422,
        detail="CVE list JSON must be a list, an object with 'cve_ids', a single {'cve_id': ...}, or JSON Lines.",
    )


def get_cve_ids_from_s3_list(key: Optional[str] = None) -> List[str]:
    key = key or CVE_LIST_S3_KEY
    bucket = require_s3_bucket()

    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        text = obj["Body"].read().decode("utf-8")
    except ClientError as exc:
        if exc.response["Error"].get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail=f"CVE list not found at s3://{bucket}/{key}") from exc
        logger.exception("Failed to read CVE list from S3")
        raise HTTPException(status_code=502, detail=f"S3 read failed: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"CVE list at s3://{bucket}/{key} is not valid UTF-8.") from exc

    try:
        raw = json.loads(text)
        return normalize_cve_ids(_extract_cve_ids_from_loaded_json(raw))
    except json.JSONDecodeError:
        cve_ids: List[Any] = []
        for line_num, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid JSON Lines at s3://{bucket}/{key}, line {line_num}: {exc}",
                ) from exc
            if isinstance(obj, dict) and "cve_id" in obj:
                cve_ids.append(obj["cve_id"])
            elif isinstance(obj, str):
                cve_ids.append(obj)
            else:
                raise HTTPException(
                    status_code=422,
                    detail=f"JSON Lines line {line_num} must be a string or an object with a 'cve_id' field.",
                )
        return normalize_cve_ids(cve_ids)


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def get_cve_ids_from_dynamodb(
    table_name: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> List[str]:
    table_name = table_name or DYNAMODB_TABLE_NAME
    if not table_name:
        raise HTTPException(status_code=500, detail="DYNAMODB_TABLE_NAME is not configured on the server.")
    if status_filter and not DYNAMODB_STATUS_ATTRIBUTE:
        raise HTTPException(
            status_code=422,
            detail="status_filter was provided, but DYNAMODB_STATUS_ATTRIBUTE is not configured.",
        )

    table = dynamodb_resource.Table(table_name)

    expression_names = {"#cve": DYNAMODB_CVE_ID_ATTRIBUTE}
    scan_kwargs: Dict[str, Any] = {
        "ProjectionExpression": "#cve",
        "ExpressionAttributeNames": expression_names,
    }

    if status_filter and DYNAMODB_STATUS_ATTRIBUTE:
        expression_names["#status"] = DYNAMODB_STATUS_ATTRIBUTE
        scan_kwargs["FilterExpression"] = "#status = :status"
        scan_kwargs["ExpressionAttributeValues"] = {":status": status_filter}

    cve_ids: List[Any] = []
    try:
        while True:
            resp = table.scan(**scan_kwargs)
            for item in resp.get("Items", []) or []:
                cve_ids.append(item.get(DYNAMODB_CVE_ID_ATTRIBUTE))

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except ClientError as exc:
        logger.exception("Failed to read from DynamoDB")
        raise HTTPException(status_code=502, detail=f"DynamoDB scan failed: {exc}") from exc

    return normalize_cve_ids(cve_ids)


# ---------------------------------------------------------------------------
# S3 / serialization helpers
# ---------------------------------------------------------------------------

def flat_arrow_schema() -> "pa.Schema":
    fields = []
    for column in FLAT_CVE_COLUMNS:
        if column in TIMESTAMP_COLUMNS:
            fields.append((column, pa.timestamp("us", tz="UTC")))
        elif column in FLOAT_COLUMNS:
            fields.append((column, pa.float64()))
        elif column in INT_COLUMNS:
            fields.append((column, pa.int64()))
        elif column in BOOL_COLUMNS:
            fields.append((column, pa.bool_()))
        else:
            fields.append((column, pa.string()))
    return pa.schema(fields)


def build_flat_dataframe(records: Sequence[Dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame.from_records(records, columns=FLAT_CVE_COLUMNS if not records else None)
    df = df.reindex(columns=FLAT_CVE_COLUMNS)

    for column in TIMESTAMP_COLUMNS:
        df[column] = pd.to_datetime(df[column], errors="coerce", utc=True)
    for column in FLOAT_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce")
    for column in INT_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").astype("Int64")
    for column in BOOL_COLUMNS:
        df[column] = df[column].astype("boolean")
    for column in STRING_COLUMNS:
        df[column] = df[column].astype("string")

    return df


def upload_json_to_s3(payload: Dict[str, Any], key: str) -> None:
    bucket = require_s3_bucket()
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as exc:
        logger.exception("Failed to upload JSON to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {exc}") from exc


def upload_jsonl_to_s3(records: Sequence[Dict[str, Any]], key: str) -> None:
    bucket = require_s3_bucket()
    body = "".join(json.dumps(record, default=str, separators=(",", ":")) + "\n" for record in records).encode("utf-8")
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/x-ndjson",
        )
    except ClientError as exc:
        logger.exception("Failed to upload JSON Lines to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {exc}") from exc


def upload_parquet_to_s3(records: Sequence[Dict[str, Any]], key: str) -> None:
    bucket = require_s3_bucket()
    df = build_flat_dataframe(records)
    table = pa.Table.from_pandas(df, schema=flat_arrow_schema(), preserve_index=False)

    buffer = io.BytesIO()
    pq.write_table(table, buffer, compression="snappy")

    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=buffer.getvalue(),
            ContentType="application/vnd.apache.parquet",
        )
    except ClientError as exc:
        logger.exception("Failed to upload Parquet to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {exc}") from exc


def read_json_from_s3(key: str) -> Dict[str, Any]:
    bucket = require_s3_bucket()
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        return json.loads(obj["Body"].read().decode("utf-8"))
    except ClientError as exc:
        if exc.response["Error"].get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail=f"No object found at key: {key}") from exc
        logger.exception("Failed to read from S3")
        raise HTTPException(status_code=502, detail=f"S3 read failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"Object at key {key} is not valid JSON: {exc}") from exc


def read_jsonl_from_s3(key: str) -> List[Dict[str, Any]]:
    bucket = require_s3_bucket()
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        text = obj["Body"].read().decode("utf-8")
    except ClientError as exc:
        if exc.response["Error"].get("Code") in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail=f"No object found at key: {key}") from exc
        logger.exception("Failed to read from S3")
        raise HTTPException(status_code=502, detail=f"S3 read failed: {exc}") from exc

    records: List[Dict[str, Any]] = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Corrupt JSON Lines at s3://{bucket}/{key}, line {line_num}: {exc}",
            ) from exc
        if not isinstance(obj, dict):
            raise HTTPException(status_code=502, detail=f"JSON Lines record at line {line_num} is not an object.")
        records.append(obj)
    return records


def make_run_stem(basename: str, now: Optional[datetime] = None) -> str:
    now = now or datetime.now(timezone.utc)
    date_part = now.strftime("%Y-%m-%d")
    time_part = now.strftime("%H%M%S")
    token = uuid.uuid4().hex[:8]
    return f"{basename}_{date_part}_{time_part}_{token}"


def keys_for_stem(stem: str) -> Tuple[str, str, str]:
    return (
        f"{RAW_PREFIX}{stem}.json",
        f"{FLAT_PREFIX}{stem}.json",
        f"{FLAT_PREFIX}{stem}.parquet",
    )


def build_output_keys(basename: str) -> Tuple[str, str, str]:
    require_s3_bucket()
    return keys_for_stem(make_run_stem(basename))


def write_all_outputs(result: Dict[str, Any], basename: str) -> Tuple[str, str, str]:
    """
    Write raw JSON, flat Parquet, and flat JSONL.

    The flat JSONL object is written last because /cves/latest discovers flat
    JSON files. If Parquet creation fails, the dashboard will not pick up a
    half-published run.
    """
    raw_key, jsonl_key, parquet_key = build_output_keys(basename)
    flat_records = flatten_result(result)

    upload_json_to_s3(result, raw_key)
    upload_parquet_to_s3(flat_records, parquet_key)
    upload_jsonl_to_s3(flat_records, jsonl_key)

    logger.info("Wrote %s flat CVE rows to s3://%s/%s", len(flat_records), S3_BUCKET_NAME, jsonl_key)
    return raw_key, jsonl_key, parquet_key


def find_latest_key(prefix: str = FLAT_PREFIX, suffix: str = ".json") -> Optional[str]:
    bucket = require_s3_bucket()
    paginator = s3_client.get_paginator("list_objects_v2")
    latest_key: Optional[str] = None
    latest_time = None

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []) or []:
            key = obj.get("Key", "")
            if suffix and not key.endswith(suffix):
                continue
            if latest_time is None or obj["LastModified"] > latest_time:
                latest_time = obj["LastModified"]
                latest_key = key

    return latest_key


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/cves/sync", response_model=SyncResult)
async def sync_cves(
    keyword_search: Optional[str] = Query(None, description="Free-text search, e.g. 'apache log4j'"),
    cve_id: Optional[str] = Query(None, description="Fetch a single CVE, e.g. 'CVE-2021-44228'"),
    pub_start_date: Optional[str] = Query(None, description="ISO date, requires pub_end_date"),
    pub_end_date: Optional[str] = Query(None, description="ISO date, requires pub_start_date"),
    severity: Optional[str] = Query(None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    max_records: Optional[int] = Query(None, description="Cap total records fetched"),
) -> SyncResult:
    result = await fetch_cves(
        keyword_search=keyword_search,
        cve_id=cve_id,
        pub_start_date=pub_start_date,
        pub_end_date=pub_end_date,
        severity=severity,
        max_records=max_records,
    )

    raw_key, jsonl_key, parquet_key = await asyncio.to_thread(write_all_outputs, result, BASENAME_SYNC)

    return SyncResult(
        s3_key=raw_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        total_results=result["totalResults"],
        results_fetched=result["resultsFetched"],
        synced_at=result["fetchedAt"],
    )


@app.post("/cves/sync-from-list", response_model=ListSyncResult)
async def sync_cves_from_list(
    source_key: Optional[str] = Query(None, description="Override CVE_LIST_S3_KEY for this call"),
) -> ListSyncResult:
    key = source_key or CVE_LIST_S3_KEY
    cve_ids = await asyncio.to_thread(get_cve_ids_from_s3_list, key)
    if not cve_ids:
        raise HTTPException(status_code=404, detail=f"No CVE IDs found in s3://{S3_BUCKET_NAME}/{key}")

    result = await fetch_specific_cves(cve_ids)
    raw_key, jsonl_key, parquet_key = await asyncio.to_thread(write_all_outputs, result, BASENAME_LIST)

    return ListSyncResult(
        s3_key=raw_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        source_key=key,
        requested=result["requested"],
        results_fetched=result["resultsFetched"],
        not_found=result["notFound"],
        error_count=len(result.get("errors", [])),
        synced_at=result["fetchedAt"],
    )


@app.post("/cves/sync-from-dynamodb", response_model=DynamoSyncResult)
async def sync_cves_from_dynamodb(
    table_name: Optional[str] = Query(None, description="Override DYNAMODB_TABLE_NAME for this call"),
    status_filter: Optional[str] = Query(None, description="Only check items whose status attribute equals this value"),
) -> DynamoSyncResult:
    cve_ids = await asyncio.to_thread(get_cve_ids_from_dynamodb, table_name, status_filter)
    if not cve_ids:
        raise HTTPException(status_code=404, detail="No CVE IDs found in DynamoDB to check.")

    result = await fetch_specific_cves(cve_ids)
    raw_key, jsonl_key, parquet_key = await asyncio.to_thread(write_all_outputs, result, BASENAME_DYNAMO)

    return DynamoSyncResult(
        s3_key=raw_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        requested=result["requested"],
        results_fetched=result["resultsFetched"],
        not_found=result["notFound"],
        error_count=len(result.get("errors", [])),
        synced_at=result["fetchedAt"],
    )


@app.get("/cves/latest")
def get_latest_cves(
    limit: Optional[int] = Query(None, ge=1, description="Optionally limit returned records for dashboard/API testing"),
) -> Dict[str, Any]:
    latest_key = find_latest_key()
    if not latest_key:
        raise HTTPException(status_code=404, detail="No CVE data has been synced yet.")

    records = read_jsonl_from_s3(latest_key)
    if limit is not None:
        records = records[:limit]
    return {"s3_key": latest_key, "count": len(records), "records": records}


@app.get("/cves/latest-raw")
def get_latest_raw_cves() -> Dict[str, Any]:
    latest_key = find_latest_key(prefix=RAW_PREFIX, suffix=".json")
    if not latest_key:
        raise HTTPException(status_code=404, detail="No raw CVE data has been synced yet.")
    return read_json_from_s3(latest_key)
