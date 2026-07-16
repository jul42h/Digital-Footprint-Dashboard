# Digital Footprint Dashboard

Fresno State **AI Risk Intelligence** dashboard for external footprint visibility.
Scan findings from DynamoDB power curated AI summaries, risk scoring, threat context,
and remediation priorities — plus inventory pages for CVEs, assets, vendors, and analytics.

Served by the **footprint-api** FastAPI app with live DynamoDB data.

**Full architecture and section-by-section guide:** [DASHBOARD.md](./DASHBOARD.md)

## Project structure

| Path | Description |
|------|-------------|
| `frontend/` | React dashboard (Vite + TypeScript, Fresno State branding) |
| `frontend/dist/` | Production build output (served by FastAPI) |
| `footprint-api/` | FastAPI server (DynamoDB + AI Lambda relay + static UI) |
| `frontend_mount.py` | SPA routing helper used by the API |

## Quick start

### 1. Install dependencies

```bash
cd frontend && npm install && cd ..
pip3 install -r footprint-api/requirements.txt
export DYNAMODB_TABLE_NAME=enriched-database
export AWS_REGION=us-west-2
```

### 2. Build the frontend

```bash
npm run build
```

### 3. Start the API

```bash
npm run api
```

Open **http://localhost:8000** — the dashboard and API share the same origin.

See `footprint-api/README.md` for endpoint details and environment variables.

## Routes

| Route | Purpose |
|-------|---------|
| `/` | Risk intelligence **home** — AI summary, risk score, threat signals, top findings, highest-risk assets, prioritized remediation |
| `/insights` | Full **AI Risk Intelligence** — curated panels for every Lambda intent |
| `/cves` | Security issues inventory |
| `/threats` | Threat category guide |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation tracking |
| `/vendors` | Software providers and products |
| `/analytics` | Deeper charts — geography, ports, OS |
| `/guide` | Metric & terminology reference |
| `/settings` | Data source and remediation preferences |

**Ask AI** is the floating panel (bottom-right FAB), not a sidebar route: guided questions, CVE lookup, and remediation for a selected set of findings.

## Optional: Vite dev server

Use while editing React code (port 5173, proxies `/api` to localhost:8000):

```bash
cd frontend
npm run dev
```

Keep the API running in another terminal (`npm run api` or `npm run api:serve`).

## Environment variables

**API** — see `footprint-api/README.md`

**Frontend dev only** (`frontend/.env`):

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | API base URL (empty = relative paths / dev proxy) |

When served from FastAPI, leave `VITE_API_URL` unset.

## License

Private / prototype.
