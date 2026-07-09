"""
NVD CVE -> S3 pipeline, exposed via FastAPI.

Endpoints:
    POST /cves/sync                 Fetch CVEs from NVD (with optional filters) and upload to S3
    POST /cves/sync-from-list       Fetch only the CVE IDs listed in a JSON file in S3 and upload results to S3
    POST /cves/sync-from-dynamodb   Fetch only the CVE IDs listed in your DynamoDB table and upload to S3
    GET  /cves/latest               Read the most recently synced CVE file back out of S3
    GET  /health                    Basic health check

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
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List

import boto3
import httpx
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
    total_results: int
    results_fetched: int
    synced_at: str


class DynamoSyncResult(BaseModel):
    s3_key: str
    requested: int
    results_fetched: int
    not_found: List[str]
    synced_at: str


class ListSyncResult(BaseModel):
    s3_key: str
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

    return SyncResult(
        s3_key=s3_key,
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

    return ListSyncResult(
        s3_key=s3_key,
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

    return DynamoSyncResult(
        s3_key=s3_key,
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