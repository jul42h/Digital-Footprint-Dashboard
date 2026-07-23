# Footprint API

FastAPI server for the Digital Footprint Dashboard. Reads findings from DynamoDB,
relays AI analysis to the **AI Risk Analyzer** Lambda, and serves the built React UI
from `../frontend/dist`.

## Setup

From the **repo root**:

```bash
pip3 install -r footprint-api/requirements.txt
export DYNAMODB_TABLE_NAME=enriched-database
export AWS_REGION=us-west-2
```

Optional AI Lambda relay:

```bash
export CVE_ANALYZER_LAMBDA_NAME=ai-risk-analyzer
export CVE_ANALYZER_LAMBDA_REGION=us-west-2
```

Build the frontend (one time, or after UI changes):

```bash
npm run build
```

## Run

```bash
cd footprint-api
uvicorn app:app --reload --port 8000 --reload-dir ../frontend/src
```

Or from the repo root: `npm run api` (rebuilds the frontend, then starts the server).

For a faster restart when the UI is already built: `npm run api:serve`.

Open **http://localhost:8000**. API docs: http://localhost:8000/docs

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/dashboard` | Full dashboard payload for the React app |
| `POST` | `/api/v1/dashboard/refresh` | Re-scan DynamoDB and refresh cached dashboard |
| `POST` | `/api/cve-analysis` | AI risk intelligence via Lambda |
| `GET` | `/findings` | Raw findings (`?ip=` optional) |
| `GET` | `/findings/{ip}/{cve_id}` | Single finding |
| `GET` | `/health` | Legacy health check |

## CVE AI analysis

```
React
  → POST /api/cve-analysis
     {
       "cve_ids": [...],          # optional if findings present (max 25)
       "findings": [{ ... }],     # preferred structured context (max 100)
       "intent": "brief" | "insights" | "risk_score" | "threat_intel"
                 | "critical_findings" | "risk_assets" | "remediate" | "ask_ai",
       "question": "...",         # required for ask_ai
       "mode": "brief" | "detail" # legacy; ignored when intent is set
     }
  → Lambda → {
       status, intent, ai_summary, ai_summary_format,
       risk_score, signal_summary, cve_ids_analyzed, ...
     }
```

| Dashboard surface | `intent` | Output shape |
|-------------------|----------|--------------|
| Home / Insights AI summary | `brief` | prose |
| Insights — AI insights | `insights` | sections |
| Insights — Risk score | `risk_score` | prose (+ computed `risk_score` object) |
| Insights — Threat intelligence | `threat_intel` | sections |
| Insights — Top critical findings | `critical_findings` | sections |
| Insights — Highest-risk assets | `risk_assets` | sections |
| Insights / Ask AI remediate | `remediate` | sections |
| Ask AI questions / CVE lookup | `ask_ai` | prose |

The Lambda computes `risk_score` from posture (not the model). FastAPI does not call Bedrock directly.

Legacy Lambda aliases (if calling Lambda directly): `analyze` → `insights`, `next_steps` → `remediate`. The FastAPI request model accepts the canonical intent names above.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DYNAMODB_TABLE_NAME` | `enriched-database` | Findings table |
| `AWS_REGION` | `us-west-2` | AWS region |
| `CVE_ANALYZER_LAMBDA_NAME` | `ai-risk-analyzer` | Lambda to invoke |
| `CVE_ANALYZER_LAMBDA_REGION` | `us-west-2` | Lambda region |
| `CVE_ANALYZER_LAMBDA_TIMEOUT_SECONDS` | `60` | Client read timeout budget |
| `FRONTEND_DIST` | `../frontend/dist` | Built UI path |
| `FRONTEND_DEV_URL` | unset | Proxy UI to Vite when set |
| `FRONTEND_ALWAYS_REBUILD` | unset | Force UI rebuild on API start |
| `IP_MASK_SALT` | unset (required once a viewer-role user exists) | Salts the opaque per-host IP token returned to viewers on `/api/v1/dashboard` — see `ip_masking.py`. Generate with `python -c "import secrets; print(secrets.token_urlsafe(64))"`. Same fail-loudly pattern as `AUTH_JWT_SECRET` (`auth/README.md`): the API raises `RuntimeError` the first time a viewer requests the dashboard if this isn't set, rather than falling back to an unsalted/guessable token. |
