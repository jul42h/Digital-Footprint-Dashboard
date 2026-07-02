# Digital Footprint Dashboard

React dashboard for security posture, CVEs, IPs, vendors, and analytics — served by the included **footprint-api** FastAPI app.

## Project structure

| Path | Description |
|------|-------------|
| `frontend/` | React dashboard (Vite + TypeScript) |
| `frontend/dist/` | Production build output (served by FastAPI) |
| `footprint-api/` | FastAPI server (DynamoDB + static UI) |
| `frontend_mount.py` | SPA routing helper used by the API |
| `findings/` | Findings hooks and related utilities |

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

Open **http://localhost:8000** — the dashboard and API share the same origin, so no `VITE_API_URL` is needed.

See `footprint-api/README.md` for endpoint details and environment variables.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/dashboard` | Full dashboard payload |
| `POST` | `/api/v1/dashboard/refresh` | Trigger data refresh |
| `GET` | `/findings` | Findings list (optional `?ip=` filter) |

If the API is unavailable, the frontend falls back to `/data/shodan_data.xlsx` in the build.

## Optional: Vite dev server

Only use this while editing React code. It runs on port 5173 and proxies `/api` to localhost:8000:

```bash
cd frontend
npm run dev
```

Keep the API running separately in another terminal (`npm run api`).

## Environment variables

**API** (`footprint-api/.env` or shell exports):

| Variable | Description |
|----------|-------------|
| `DYNAMODB_TABLE_NAME` | DynamoDB table (default: `enriched-database`) |
| `AWS_REGION` | AWS region (default: `us-west-2`) |
| `FRONTEND_DIST` | Override path to `frontend/dist` |

**Frontend dev only** (`frontend/.env`):

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | API base URL (empty = relative paths / dev proxy) |
| `VITE_USE_API` | `true` to prefer API over Excel |

When served from FastAPI, leave `VITE_API_URL` unset.

## License

Private / prototype.
