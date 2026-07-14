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
| `POST` | `/api/cve-analysis` | AI summary for 1–5 CVE IDs via the AI Risk Analyzer Lambda |
| `GET` | `/findings` | Raw findings (`?ip=` optional) |
| `GET` | `/findings/{ip}/{cve_id}` | Single finding |
| `GET` | `/health` | Legacy health check |

## CVE AI analysis

```
React (home brief / Analyze panel / CVE detail)
   → POST /api/cve-analysis  { "cve_ids": [...], "mode": "brief"|"detail" }
   → ask_ai.cve_dashboard_api (boto3 Lambda invoke)
   → AI Risk Analyzer Lambda
   → { status, cve_ids_analyzed, ai_summary, … }
```

| Dashboard surface | `mode` | Expected `ai_summary` style |
|-------------------|--------|-----------------------------|
| Home priority brief | `brief` | 2–3 dense sentences: meaning + risk signal + next step (short, not shallow). |
| Analyze panel / CVE detail | `detail` | Full write-up: impact, exploitability, affected systems, remediation order. |

The API never calls Bedrock directly. Grant `lambda:InvokeFunction` on the analyzer Lambda to the runtime role/credentials.

### Lambda changes required (same OpenAI model)

Keep one OpenAI model for both modes. Speed and tone come from **prompt + tokens + context**, not a second model.

1. **Packaging:** include `openai` (layer or zip).
2. **Accept `mode`** (default `detail` if missing):
   ```json
   { "cve_ids": ["CVE-…"], "mode": "brief" }
   ```
3. **Same model, different completion budget:**
   - **`brief`:** `max_tokens` ≈ 220–280. Prompt for **2–3 dense sentences** (not a slogan): what the priority findings mean for this footprint, the main risk signal (e.g. KEV / high CVSS), and one concrete next step. Slim fields: id, severity, KEV/EPSS, short title.
   - **`detail`:** `max_tokens` ≈ 600–900; fuller context; analyst-style write-up.
4. **No model retries on `brief`** (fail once, surface error) so a hung call doesn’t double the wait.
5. **Reuse the OpenAI client** across warm invokes (create outside the handler or cache globally).
6. **Optional infra:** provisioned concurrency = 1 (or a scheduled warm ping) to avoid cold starts — still the same model.
7. Return the existing response shape (`status`, `ai_summary`, `cve_ids_analyzed`, …).

### Dashboard speed behaviors (already in the UI)

- Home brief is **on-demand** (“Generate brief”), not on every page load.
- Successful analyses are cached in **memory + sessionStorage** for 30 minutes (shared by home, panel, and CVE detail).
- Priority CVE chips render immediately; AI text loads only when requested.

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
