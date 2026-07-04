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
| `GET` | `/findings` | Raw findings (`?ip=` optional) |
| `GET` | `/findings/{ip}/{cve_id}` | Single finding |
| `GET` | `/health` | Legacy health check |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DYNAMODB_TABLE_NAME` | `enriched-database` | DynamoDB table name |
| `AWS_REGION` | `us-west-2` | AWS region |
| `FRONTEND_DIST` | `../frontend/dist` | Path to built React app |
| `FRONTEND_DEV_URL` | _(unset)_ | Proxy UI to Vite dev server (e.g. `http://127.0.0.1:5173`) |
| `FRONTEND_ALWAYS_REBUILD` | _(unset)_ | Set to `1` to run `npm run build` on every API start |
| `CORS_ORIGINS` | localhost dev ports | Comma-separated allowed origins |
