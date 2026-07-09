"""
NVD CVE -> S3 pipeline, exposed via FastAPI.

Endpoints:
    POST /cves/sync                 Fetch CVEs from NVD (with optional filters) and upload to S3
    POST /cves/sync-from-list       Fetch only the CVE IDs listed in a JSON file in S3 and upload results to S3
    POST /cves/sync-from-dynamodb   Fetch only the CVE IDs listed in your DynamoDB table and upload to S3
    GET  /cves/latest               Read the most recently synced CVE file back out of S3
    GET  /health                    Basic health check

Each sync endpoint writes three objects to S3 under the 'cves/' prefix:
    *.json     the raw, nested NVD API response (kept for archival/debugging)
    *.jsonl    one flat JSON object per line, one line per CVE
    *.parquet  the same flat, one-row-per-CVE records as a Parquet file

The .jsonl/.parquet records have NO nested lists or objects — every CVE's
multi-valued fields (descriptions, CVSS metrics for each version, weaknesses/
CWEs, references, CPE matches) are collapsed into a single row with
delimited-string columns (see `flatten_vulnerability` / FLAT_CVE_COLUMNS),
so the output loads directly into a database table.

Environment variables (set these in a .env file or your deployment config):
    AWS_ACCESS_KEY_ID              (optional if using IAM role / default credential chain)
    AWS_SECRET_ACCESS_KEY          (optional if using IAM role / default credential chain)
    AWS_REGION                     e.g. "us-east-1"
    S3_BUCKET_NAME                 name of the bucket to write to
    NVD_API_KEY                    optional but strongly recommended (raises NVD rate limit from 5/30s to 50/30s)
    CVE_LIST_S3_KEY                key of the JSON file in S3 holding your unique CVE ID list (default: "cves/cve_watchlist.json")
    DYNAMODB_TABLE_NAME            name of the DynamoDB table holding the CVE IDs you want to check
    DYNAMODB_CVE_ID_ATTRIBUTE      attribute name in that table that holds the CVE ID (default: "cve_id")
    DYNAMODB_STATUS_ATTRIBUTE      optional attribute name to filter which items get checked (e.g. "status")
"""

import os
import io
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List

import boto3
import httpx
import pandas as pd
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

load_dotenv()  # reads variables from a .env file in the working directory, if present

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nvd-cve-sync")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME")
DYNAMODB_CVE_ID_ATTRIBUTE = os.getenv("DYNAMODB_CVE_ID_ATTRIBUTE", "cve_id")
DYNAMODB_STATUS_ATTRIBUTE = os.getenv("DYNAMODB_STATUS_ATTRIBUTE")  # optional, e.g. "status"

CVE_LIST_S3_KEY = os.getenv("CVE_LIST_S3_KEY", "cves/cve_watchlist.json")

if not S3_BUCKET_NAME:
    logger.warning("S3_BUCKET_NAME is not set — /cves/sync will fail until it is configured.")

# boto3 will automatically use AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from env
# if present, or fall back to an IAM role / shared credentials file / etc.
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
    synced_at: str


class ListSyncResult(BaseModel):
    s3_key: str
    jsonl_key: str
    parquet_key: str
    source_key: str
    requested: int
    results_fetched: int
    not_found: List[str]
    synced_at: str


# ---------------------------------------------------------------------------
# NVD fetch logic
# ---------------------------------------------------------------------------

async def fetch_cves(
    keyword_search: Optional[str] = None,
    cve_id: Optional[str] = None,
    pub_start_date: Optional[str] = None,   # ISO 8601, e.g. 2024-01-01T00:00:00.000
    pub_end_date: Optional[str] = None,
    severity: Optional[str] = None,          # LOW, MEDIUM, HIGH, CRITICAL (CVSS v3)
    results_per_page: int = 2000,
    max_records: Optional[int] = None,       # cap total records pulled; None = pull everything available
) -> dict:
    """
    Pulls CVE records from the NVD 2.0 REST API, paginating as needed.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }
    if keyword_search:
        params["keywordSearch"] = keyword_search
    if cve_id:
        params["cveId"] = cve_id
    if pub_start_date and pub_end_date:
        params["pubStartDate"] = pub_start_date
        params["pubEndDate"] = pub_end_date
    if severity:
        params["cvssV3Severity"] = severity.upper()

    all_vulnerabilities = []
    total_results = None

    # NVD enforces a rate limit — without an API key: 5 requests / 30s.
    # With a key: 50 requests / 30s. httpx timeout is generous since NVD can be slow.
    async with httpx.AsyncClient(timeout=60.0) as client:
        while True:
            resp = await client.get(NVD_BASE_URL, params=params, headers=headers)

            if resp.status_code == 403:
                raise HTTPException(
                    status_code=502,
                    detail="NVD API rejected the request (403). Check NVD_API_KEY or rate limits.",
                )
            resp.raise_for_status()
            data = resp.json()

            total_results = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            all_vulnerabilities.extend(vulns)

            fetched_so_far = len(all_vulnerabilities)
            logger.info(f"Fetched {fetched_so_far}/{total_results} CVEs")

            if max_records and fetched_so_far >= max_records:
                all_vulnerabilities = all_vulnerabilities[:max_records]
                break

            next_index = params["startIndex"] + results_per_page
            if next_index >= total_results:
                break
            params["startIndex"] = next_index

    return {
        "totalResults": total_results,
        "resultsFetched": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }


async def fetch_specific_cves(cve_ids: List[str]) -> dict:
    """
    Fetches a specific list of CVE IDs from NVD, one request per CVE
    (the NVD 2.0 API only supports looking up a single cveId per call).

    Respects NVD's rate limit by spacing requests out:
      - No API key: 5 requests / 30s  -> ~6s between requests
      - With API key: 50 requests / 30s -> ~0.6s between requests
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    delay_seconds = 0.6 if NVD_API_KEY else 6.0

    found = []
    not_found = []
    errors = []

    async with httpx.AsyncClient(timeout=60.0) as client:
        for i, cve_id in enumerate(cve_ids):
            try:
                resp = await client.get(
                    NVD_BASE_URL, params={"cveId": cve_id}, headers=headers
                )
                if resp.status_code == 403:
                    raise HTTPException(
                        status_code=502,
                        detail="NVD API rejected the request (403). Check NVD_API_KEY or rate limits.",
                    )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    found.extend(vulns)
                else:
                    not_found.append(cve_id)
            except httpx.HTTPStatusError as e:
                logger.warning(f"NVD lookup failed for {cve_id}: {e}")
                errors.append({"cve_id": cve_id, "error": str(e)})

            logger.info(f"Checked {i + 1}/{len(cve_ids)} CVEs from DynamoDB list")

            # Don't sleep after the last request
            if i < len(cve_ids) - 1:
                await asyncio.sleep(delay_seconds)

    return {
        "requested": len(cve_ids),
        "resultsFetched": len(found),
        "notFound": not_found,
        "errors": errors,
        "vulnerabilities": found,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Flattening logic
# ---------------------------------------------------------------------------
#
# The raw NVD payload is deeply nested (descriptions[], metrics.cvssMetricV2/
# V30/V31/V40[], weaknesses[].description[], configurations[].nodes[].cpeMatch[],
# references[]). For JSONL/Parquet output we want one row per CVE with every
# multi-valued field collapsed into a delimited string column, so the result
# loads cleanly into a database table with no nested/struct columns.

_LIST_SEP = "; "


def _join_unique(values: List[str]) -> str:
    """De-dupes (preserving order) and joins a list of strings for a flat column."""
    seen = set()
    out = []
    for v in values:
        if v is None:
            continue
        v = str(v)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return _LIST_SEP.join(out)


def _first_english_description(descriptions: List[dict]) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return (descriptions or [{}])[0].get("value", "") if descriptions else ""


def _extract_cvss_metric(metrics: dict, key: str) -> dict:
    """
    Pulls out the first metric entry for a given NVD metrics key
    (cvssMetricV2, cvssMetricV30, cvssMetricV31, cvssMetricV40), preferring
    the entry whose source is the primary NVD source if more than one exists.
    """
    entries = (metrics or {}).get(key, [])
    if not entries:
        return {}
    primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
    cvss_data = primary.get("cvssData", {}) or {}
    return {
        "vector": cvss_data.get("vectorString"),
        "base_score": cvss_data.get("baseScore"),
        # v2 stores severity at the metric level; v3.x/v4 store it in cvssData
        "base_severity": primary.get("baseSeverity") or cvss_data.get("baseSeverity"),
        "exploitability_score": primary.get("exploitabilityScore"),
        "impact_score": primary.get("impactScore"),
    }


def _extract_cwe_ids(weaknesses: List[dict]) -> List[str]:
    cwe_ids = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value"):
                cwe_ids.append(d["value"])
    return cwe_ids


def _extract_cpe_criteria(configurations: List[dict]) -> List[str]:
    criteria = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                c = match.get("criteria")
                if c:
                    criteria.append(c)
    return criteria


def _extract_vendors_and_products(cpe_criteria: List[str]) -> (List[str], List[str]):
    """
    CPE 2.3 URIs look like: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    """
    vendors, products = [], []
    for c in cpe_criteria:
        parts = c.split(":")
        if len(parts) >= 5:
            vendors.append(parts[3])
            products.append(parts[4])
    return vendors, products


def flatten_vulnerability(vuln: dict, fetched_at: Optional[str] = None) -> dict:
    """Flattens a single NVD `vulnerabilities[]` entry into one flat, non-nested dict."""
    cve = vuln.get("cve", {})

    metrics = cve.get("metrics", {})
    v2 = _extract_cvss_metric(metrics, "cvssMetricV2")
    v30 = _extract_cvss_metric(metrics, "cvssMetricV30")
    v31 = _extract_cvss_metric(metrics, "cvssMetricV31")
    v40 = _extract_cvss_metric(metrics, "cvssMetricV40")

    references = cve.get("references", [])
    cpe_criteria = _extract_cpe_criteria(cve.get("configurations", []))
    vendors, products = _extract_vendors_and_products(cpe_criteria)

    return {
        "cve_id": cve.get("id"),
        "source_identifier": cve.get("sourceIdentifier"),
        "vuln_status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": _first_english_description(cve.get("descriptions", [])),
        "cwe_ids": _join_unique(_extract_cwe_ids(cve.get("weaknesses", []))),
        "cvss_v2_vector": v2.get("vector"),
        "cvss_v2_base_score": v2.get("base_score"),
        "cvss_v2_base_severity": v2.get("base_severity"),
        "cvss_v2_exploitability_score": v2.get("exploitability_score"),
        "cvss_v2_impact_score": v2.get("impact_score"),
        "cvss_v30_vector": v30.get("vector"),
        "cvss_v30_base_score": v30.get("base_score"),
        "cvss_v30_base_severity": v30.get("base_severity"),
        "cvss_v30_exploitability_score": v30.get("exploitability_score"),
        "cvss_v30_impact_score": v30.get("impact_score"),
        "cvss_v31_vector": v31.get("vector"),
        "cvss_v31_base_score": v31.get("base_score"),
        "cvss_v31_base_severity": v31.get("base_severity"),
        "cvss_v31_exploitability_score": v31.get("exploitability_score"),
        "cvss_v31_impact_score": v31.get("impact_score"),
        "cvss_v40_vector": v40.get("vector"),
        "cvss_v40_base_score": v40.get("base_score"),
        "cvss_v40_base_severity": v40.get("base_severity"),
        "cvss_v40_exploitability_score": v40.get("exploitability_score"),
        "cvss_v40_impact_score": v40.get("impact_score"),
        "reference_count": len(references),
        "reference_urls": _join_unique([r.get("url") for r in references]),
        "reference_sources": _join_unique([r.get("source") for r in references]),
        "reference_tags": _join_unique([t for r in references for t in r.get("tags", [])]),
        "cpe_count": len(cpe_criteria),
        "cpe_criteria": _join_unique(cpe_criteria),
        "vendors": _join_unique(vendors),
        "products": _join_unique(products),
        "fetched_at": fetched_at,
    }


def flatten_result(result: dict) -> List[dict]:
    """Flattens an entire fetch result (as returned by fetch_cves / fetch_specific_cves)."""
    fetched_at = result.get("fetchedAt")
    return [flatten_vulnerability(v, fetched_at=fetched_at) for v in result.get("vulnerabilities", [])]


# Column order/schema for flatten_vulnerability's output, used to give an empty
# result set (e.g. zero matches) a well-defined Parquet schema instead of none.
FLAT_CVE_COLUMNS = [
    "cve_id", "source_identifier", "vuln_status", "published", "last_modified",
    "description", "cwe_ids",
    "cvss_v2_vector", "cvss_v2_base_score", "cvss_v2_base_severity",
    "cvss_v2_exploitability_score", "cvss_v2_impact_score",
    "cvss_v30_vector", "cvss_v30_base_score", "cvss_v30_base_severity",
    "cvss_v30_exploitability_score", "cvss_v30_impact_score",
    "cvss_v31_vector", "cvss_v31_base_score", "cvss_v31_base_severity",
    "cvss_v31_exploitability_score", "cvss_v31_impact_score",
    "cvss_v40_vector", "cvss_v40_base_score", "cvss_v40_base_severity",
    "cvss_v40_exploitability_score", "cvss_v40_impact_score",
    "reference_count", "reference_urls", "reference_sources", "reference_tags",
    "cpe_count", "cpe_criteria", "vendors", "products", "fetched_at",
]


# ---------------------------------------------------------------------------
# CVE list (S3 JSON file) helpers
# ---------------------------------------------------------------------------

def get_cve_ids_from_s3_list(key: Optional[str] = None) -> List[str]:
    """
    Reads a CVE ID list from S3. Supports several shapes:
      1. A plain JSON array of strings:        ["CVE-2021-44228", "CVE-2022-1234"]
      2. An object with a "cve_ids" field:      {"cve_ids": ["CVE-2021-44228", "CVE-2022-1234"]}
      3. JSON Lines — one object per line:      {"cve_id": "CVE-2021-44228"}
                                                 {"cve_id": "CVE-2022-1234"}
    """
    key = key or CVE_LIST_S3_KEY
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3_BUCKET_NAME is not configured on the server.")

    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key)
        body = obj["Body"].read()
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail=f"CVE list not found at s3://{S3_BUCKET_NAME}/{key}")
        logger.exception("Failed to read CVE list from S3")
        raise HTTPException(status_code=502, detail=f"S3 read failed: {e}")

    text = body.decode("utf-8")

    # Try parsing as a single JSON document first (array, or {"cve_ids": [...]})
    try:
        raw = json.loads(text)
        if isinstance(raw, list):
            cve_ids = raw
        elif isinstance(raw, dict) and "cve_ids" in raw:
            cve_ids = raw["cve_ids"]
        elif isinstance(raw, dict) and "cve_id" in raw:
            # single-object file with just one CVE
            cve_ids = [raw["cve_id"]]
        else:
            raise HTTPException(
                status_code=422,
                detail="CVE list JSON must be a list of strings, an object with a 'cve_ids' field, "
                       "or JSON Lines of {'cve_id': ...} objects.",
            )
    except json.JSONDecodeError:
        # Not a single valid JSON document — try JSON Lines: one {"cve_id": "..."} object per line
        cve_ids = []
        for line_num, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                logger.exception(f"Invalid JSON on line {line_num} of s3://{S3_BUCKET_NAME}/{key}")
                raise HTTPException(
                    status_code=422,
                    detail=f"File at s3://{S3_BUCKET_NAME}/{key} is not valid JSON, JSON array, "
                           f"or JSON Lines — failed on line {line_num}: {e}",
                )
            if isinstance(obj, dict) and "cve_id" in obj:
                cve_ids.append(obj["cve_id"])
            elif isinstance(obj, str):
                cve_ids.append(obj)

    # de-duplicate while preserving order (cheap, but the file should already be unique)
    seen = set()
    deduped = []
    for cid in cve_ids:
        if cid and cid not in seen:
            seen.add(cid)
            deduped.append(cid)
    return deduped


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def get_cve_ids_from_dynamodb(
    table_name: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> List[str]:
    """
    Scans your DynamoDB table and returns the list of CVE IDs to check.

    Assumes each item has an attribute holding the CVE ID (DYNAMODB_CVE_ID_ATTRIBUTE,
    default "cve_id"). If DYNAMODB_STATUS_ATTRIBUTE and status_filter are both set,
    only items matching that status are returned (e.g. only items not yet checked).

    Adjust this function if your table's schema differs (e.g. if the CVE ID is
    part of a composite key, or you want to query a GSI instead of scanning).
    """
    table_name = table_name or DYNAMODB_TABLE_NAME
    if not table_name:
        raise HTTPException(status_code=500, detail="DYNAMODB_TABLE_NAME is not configured on the server.")

    table = dynamodb_resource.Table(table_name)

    scan_kwargs = {}
    if status_filter and DYNAMODB_STATUS_ATTRIBUTE:
        scan_kwargs["FilterExpression"] = "#s = :status"
        scan_kwargs["ExpressionAttributeNames"] = {"#s": DYNAMODB_STATUS_ATTRIBUTE}
        scan_kwargs["ExpressionAttributeValues"] = {":status": status_filter}

    cve_ids = []
    try:
        while True:
            resp = table.scan(**scan_kwargs)
            for item in resp.get("Items", []):
                cve_id = item.get(DYNAMODB_CVE_ID_ATTRIBUTE)
                if cve_id:
                    cve_ids.append(cve_id)

            if "LastEvaluatedKey" not in resp:
                break
            scan_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    except ClientError as e:
        logger.exception("Failed to read from DynamoDB")
        raise HTTPException(status_code=502, detail=f"DynamoDB scan failed: {e}")

    # de-duplicate while preserving order
    seen = set()
    deduped = []
    for cid in cve_ids:
        if cid not in seen:
            seen.add(cid)
            deduped.append(cid)
    return deduped


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------

def upload_json_to_s3(payload: dict, key: str) -> None:
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3_BUCKET_NAME is not configured on the server.")
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Body=json.dumps(payload, default=str).encode("utf-8"),
            ContentType="application/json",
        )
    except ClientError as e:
        logger.exception("Failed to upload to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {e}")


def upload_jsonl_to_s3(records: List[dict], key: str) -> None:
    """Writes a list of flat dicts as newline-delimited JSON (one object per line)."""
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3_BUCKET_NAME is not configured on the server.")
    body = "\n".join(json.dumps(r, default=str) for r in records).encode("utf-8")
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Body=body,
            ContentType="application/jsonl",
        )
    except ClientError as e:
        logger.exception("Failed to upload JSONL to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {e}")


def upload_parquet_to_s3(records: List[dict], key: str) -> None:
    """Writes a list of flat dicts as a Parquet file (no nested/struct columns)."""
    if not S3_BUCKET_NAME:
        raise HTTPException(status_code=500, detail="S3_BUCKET_NAME is not configured on the server.")

    df = pd.DataFrame.from_records(records, columns=FLAT_CVE_COLUMNS if not records else None)
    buffer = io.BytesIO()
    df.to_parquet(buffer, index=False, engine="pyarrow")
    buffer.seek(0)

    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Body=buffer.getvalue(),
            ContentType="application/octet-stream",
        )
    except ClientError as e:
        logger.exception("Failed to upload Parquet to S3")
        raise HTTPException(status_code=502, detail=f"S3 upload failed: {e}")


def read_json_from_s3(key: str) -> dict:
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key)
        return json.loads(obj["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail=f"No object found at key: {key}")
        logger.exception("Failed to read from S3")
        raise HTTPException(status_code=502, detail=f"S3 read failed: {e}")


def find_latest_key(prefix: str = "cves/") -> Optional[str]:
    """Returns the most recently modified object under the given prefix."""
    paginator = s3_client.get_paginator("list_objects_v2")
    latest_key, latest_time = None, None
    for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix):
        for obj in page.get("Contents", []):
            if latest_time is None or obj["LastModified"] > latest_time:
                latest_time = obj["LastModified"]
                latest_key = obj["Key"]
    return latest_key


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/cves/sync", response_model=SyncResult)
async def sync_cves(
    keyword_search: Optional[str] = Query(None, description="Free-text search, e.g. 'apache log4j'"),
    cve_id: Optional[str] = Query(None, description="Fetch a single CVE, e.g. 'CVE-2021-44228'"),
    pub_start_date: Optional[str] = Query(None, description="ISO date, requires pub_end_date"),
    pub_end_date: Optional[str] = Query(None, description="ISO date, requires pub_start_date"),
    severity: Optional[str] = Query(None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    max_records: Optional[int] = Query(None, description="Cap total records fetched"),
):
    """
    Fetches CVEs from NVD based on optional filters and writes the result as a
    timestamped JSON object in S3 under the 'cves/' prefix. Your dashboard can
    then read the latest file via GET /cves/latest, or read directly from S3.
    """
    result = await fetch_cves(
        keyword_search=keyword_search,
        cve_id=cve_id,
        pub_start_date=pub_start_date,
        pub_end_date=pub_end_date,
        severity=severity,
        max_records=max_records,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"cves/nvd_cves_{timestamp}.json"
    upload_json_to_s3(result, s3_key)

    flat_records = flatten_result(result)
    jsonl_key = f"cves/nvd_cves_{timestamp}.jsonl"
    parquet_key = f"cves/nvd_cves_{timestamp}.parquet"
    upload_jsonl_to_s3(flat_records, jsonl_key)
    upload_parquet_to_s3(flat_records, parquet_key)

    return SyncResult(
        s3_key=s3_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        total_results=result["totalResults"],
        results_fetched=result["resultsFetched"],
        synced_at=result["fetchedAt"],
    )


@app.post("/cves/sync-from-list", response_model=ListSyncResult)
async def sync_cves_from_list(
    source_key: Optional[str] = Query(
        None, description="Override CVE_LIST_S3_KEY for this call, e.g. 'cves/cve_watchlist.json'"
    ),
):
    """
    Reads your unique CVE ID list from a JSON file in S3, looks each one up on
    NVD, and writes the combined results to S3 under the 'cves/' prefix.
    """
    key = source_key or CVE_LIST_S3_KEY
    cve_ids = get_cve_ids_from_s3_list(key=key)
    if not cve_ids:
        raise HTTPException(status_code=404, detail=f"No CVE IDs found in s3://{S3_BUCKET_NAME}/{key}")

    result = await fetch_specific_cves(cve_ids)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"cves/nvd_cves_from_list_{timestamp}.json"
    upload_json_to_s3(result, s3_key)

    flat_records = flatten_result(result)
    jsonl_key = f"cves/nvd_cves_from_list_{timestamp}.jsonl"
    parquet_key = f"cves/nvd_cves_from_list_{timestamp}.parquet"
    upload_jsonl_to_s3(flat_records, jsonl_key)
    upload_parquet_to_s3(flat_records, parquet_key)

    return ListSyncResult(
        s3_key=s3_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        source_key=key,
        requested=result["requested"],
        results_fetched=result["resultsFetched"],
        not_found=result["notFound"],
        synced_at=result["fetchedAt"],
    )


@app.post("/cves/sync-from-dynamodb", response_model=DynamoSyncResult)
async def sync_cves_from_dynamodb(
    table_name: Optional[str] = Query(None, description="Override DYNAMODB_TABLE_NAME for this call"),
    status_filter: Optional[str] = Query(
        None, description="Only check items whose DYNAMODB_STATUS_ATTRIBUTE equals this value"
    ),
):
    """
    Reads the CVE IDs you want checked from DynamoDB, looks each one up on NVD,
    and writes the combined results to S3 under the 'cves/' prefix.
    """
    cve_ids = get_cve_ids_from_dynamodb(table_name=table_name, status_filter=status_filter)
    if not cve_ids:
        raise HTTPException(status_code=404, detail="No CVE IDs found in DynamoDB to check.")

    result = await fetch_specific_cves(cve_ids)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"cves/nvd_cves_from_dynamodb_{timestamp}.json"
    upload_json_to_s3(result, s3_key)

    flat_records = flatten_result(result)
    jsonl_key = f"cves/nvd_cves_from_dynamodb_{timestamp}.jsonl"
    parquet_key = f"cves/nvd_cves_from_dynamodb_{timestamp}.parquet"
    upload_jsonl_to_s3(flat_records, jsonl_key)
    upload_parquet_to_s3(flat_records, parquet_key)

    return DynamoSyncResult(
        s3_key=s3_key,
        jsonl_key=jsonl_key,
        parquet_key=parquet_key,
        requested=result["requested"],
        results_fetched=result["resultsFetched"],
        not_found=result["notFound"],
        synced_at=result["fetchedAt"],
    )


@app.get("/cves/latest")
def get_latest_cves():
    """Reads the most recently synced CVE JSON file back out of S3 for the dashboard."""
    latest_key = find_latest_key()
    if not latest_key:
        raise HTTPException(status_code=404, detail="No CVE data has been synced yet.")
    return read_json_from_s3(latest_key)