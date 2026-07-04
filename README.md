# Digital Footprint Dashboard

Fresno State cybersecurity dashboard for external footprint visibility — CVEs, IP assets, remediations, vendors, and analytics. Served by the **footprint-api** FastAPI app with DynamoDB or Excel fallback data.

## Project structure

| Path | Description |
|------|-------------|
| `frontend/` | React dashboard (Vite + TypeScript, Fresno State branding) |
| `frontend/dist/` | Production build output (served by FastAPI) |
| `footprint-api/` | FastAPI server (DynamoDB + static UI) |
| `frontend_mount.py` | SPA routing helper used by the API |

## Quick start

### 1. Install dependencies

```bash
# Frontend
cd frontend && npm install && cd ..

# API
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
| `/` | Overview — posture bar, severity, threats, remediation queue |
| `/cves` | All security issues |
| `/threats` | Threat category guide |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation options |
| `/vendors` | Software providers and products |
| `/analytics` | Deeper charts — geography, ports, OS |
| `/settings` | Data source and theme preferences |

## Optional: Vite dev server

Use while editing React code (port 5173, proxies `/api` to localhost:8000):

```bash
cd frontend
npm run dev
```

Keep the API running in another terminal (`npm run api`).

## Environment variables

**API** — see `footprint-api/README.md`

**Frontend dev only** (`frontend/.env`):

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | API base URL (empty = relative paths / dev proxy) |
| `VITE_USE_API` | `true` to prefer API over Excel |

When served from FastAPI, leave `VITE_API_URL` unset.

## License

Private / prototype.
