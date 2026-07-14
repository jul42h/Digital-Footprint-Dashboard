# Footprint API

FastAPI server for the Digital Footprint Dashboard. Reads findings from DynamoDB and serves the built React UI from `../frontend/dist`.

## Setup

From the **repo root**:

```bash
pip3 install -r footprint-api/requirements.txt
export DYNAMODB_TABLE_NAME=enriched-database
export AWS_REGION=us-west-2
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

The API rebuilds `frontend/dist` automatically when source files change (content hash check). If the UI still looks outdated, hard-refresh the browser (Ctrl+Shift+R) or run `npm run build` from the repo root.

If `npm run dev` is already running, the API auto-proxies the UI from port 5173 so port 8000 always matches the live dev build.

Or from the repo root: `npm run api` (always rebuilds the frontend, then starts the server).

For a faster restart when the UI is already built: `npm run api:serve`.

The API auto-rebuilds `frontend/dist` on startup when source files are newer than the last build. Set `FRONTEND_ALWAYS_REBUILD=1` to force a rebuild every time.

For live UI while editing React code, run `npm run dev` in one terminal and start the API with `FRONTEND_DEV_URL=http://127.0.0.1:5173` in another — port 8000 will proxy to Vite.

Open **http://localhost:8000** for the same React dashboard as `npm run dev` — the API serves `frontend/dist` on the same origin. Hard-refresh (Ctrl+Shift+R) if you still see an old layout after a rebuild.

API docs: http://localhost:8000/docs

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/dashboard` | Full dashboard payload for the React app |
| `POST` | `/api/v1/dashboard/refresh` | Re-scan DynamoDB and refresh cached dashboard |
| `POST` | `/api/cve-analysis` | AI risk intelligence via Lambda (`findings` preferred; up to 100 findings / 25 CVE IDs; `intent`: brief \| analyze \| remediate \| next_steps) |
| `GET` | `/findings` | Raw findings (`?ip=` optional) |
| `GET` | `/findings/{ip}/{cve_id}` | Single finding |
| `GET` | `/health` | Legacy health check |

## CVE AI analysis

```
React
  → POST /api/cve-analysis
     {
       "cve_ids": [...],
       "findings": [{ "cve_id", "ip", "cvss", "epss", "kev", "summary", "port", … }],
       "mode": "brief"|"detail",
       "intent": "brief"|"analyze"|"remediate"|"next_steps"
     }
  → Lambda → { status, ai_summary, cve_ids_analyzed, intent, mode, … }
```

`findings` is preferred (structured risk context). `cve_ids` remains for compatibility.

| Dashboard surface | `intent` | `mode` | Expected `ai_summary` |
|-------------------|----------|--------|------------------------|
| Home AI brief | `brief` | `brief` | Top 5 findings: Risk Posture, What Stands Out, Priority Action |
| Analyze → Explain risk | `analyze` | `detail` | Summary, Top Risks, Why It Matters, Confidence and Gaps |
| Analyze → How to fix | `remediate` | `detail` | Priority Order, Recommended Actions, Validation, Limitations |
| Analyze → What next | `next_steps` | `detail` | Immediate, This Week, Owners, Data Needed |
| CVE detail Analyst notes | `analyze` | `detail` | Same as Explain risk |

If `intent` is omitted, it is derived from `mode` (`brief` → `brief`, `detail` → `analyze`).

Reference Lambda (copy into AWS): `ask_ai/lambda_ai_risk_analyzer.py`

The API never calls Bedrock directly. Grant `lambda:InvokeFunction` on the analyzer Lambda to the runtime role/credentials.

### Lambda behavior (aligned with repo reference)

1. **Packaging:** include `openai` (layer or zip).
2. Accept `intent` + `mode` (+ preferred `findings`).
3. Brief uses **top 5** ranked findings; other intents use up to **8** detailed findings; posture aggregates over all valid inputs (up to 500).
4. Sanitize model output (`_sanitize_output`) before returning `ai_summary`.
5. Return `status`, `ai_summary`, `cve_ids_analyzed`, `mode`, `intent`, `signal_summary`, finding counts.

### Dashboard speed behaviors (already in the UI)

- Home brief **auto-generates** when missing, when the top-5 KEV/severity signal changes, or when the last brief is **≥ 2 hours** old (manual Refresh still available).
- Successful analyses are cached in **localStorage** (brief TTL 2h; other intents TTL 30m).
## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMODB_TABLE_NAME` | `enriched-database` | DynamoDB table name |
| `AWS_REGION` | `us-west-2` | AWS region (DynamoDB, etc.) |
| `CVE_ANALYZER_LAMBDA_NAME` | `ai-risk-analyzer` | Analyzer Lambda name or ARN |
| `CVE_ANALYZER_LAMBDA_REGION` | `us-west-2` | Region where the Lambda is deployed |
| `CVE_ANALYZER_LAMBDA_TIMEOUT_SECONDS` | `60` | Must match the Lambda’s configured timeout |
| `FRONTEND_DIST` | `../frontend/dist` | Path to built React app |
| `FRONTEND_DEV_URL` | _(unset)_ | Proxy UI to Vite dev server (e.g. `http://127.0.0.1:5173`) |
| `FRONTEND_ALWAYS_REBUILD` | _(unset)_ | Set to `1` to run `npm run build` on every API start |
| `CORS_ORIGINS` | localhost dev ports | Comma-separated allowed origins |
