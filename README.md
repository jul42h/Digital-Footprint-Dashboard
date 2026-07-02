# Digital Footprint Dashboard

React dashboard for security posture, CVEs, IPs, vendors, and analytics. The UI is served by the **footprint-api** FastAPI app.

## Related repo

The API lives in **`footprint-api`** (sibling folder). See its README for setup and `uvicorn` instructions.

## Project structure

| Path | Description |
|------|-------------|
| `frontend/` | React dashboard (Vite + TypeScript) |
| `frontend/dist/` | Production build output (served by FastAPI) |
| `findings/` | Findings hooks and related utilities |
| `fastapi_integration.example.py` | Copy-paste snippet to mount the UI in FastAPI |

## Run with FastAPI (recommended)

`npm run dev` starts **Vite only** on port 5173. To run everything through uvicorn on port 8000:

### 1. Build the frontend

```bash
cd frontend
npm install
npm run build
```

Or from the repo root: `npm run build`

This creates `frontend/dist/`.

### 2. Mount the build in your FastAPI app

Register your API routes first, then mount the static files. See `frontend_mount.py`:

```python
from frontend_mount import mount_frontend

# ... your /api/v1/* and /findings routes ...

mount_frontend(app)
```

`mount_frontend()` serves real files from `frontend/dist` (assets, favicon, seal) and falls back to `index.html` for client routes like `/cves` and `/ips`. Starlette 0.49+ no longer does this with `StaticFiles(html=True)` alone.

### 3. Start uvicorn

```bash
uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000** — the dashboard and API share the same origin, so no `VITE_API_URL` is needed.

## API endpoints your FastAPI should expose

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

Keep uvicorn running separately in another terminal.

## Environment variables

Only needed for the Vite dev workflow (`frontend/.env`):

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | API base URL (empty = relative paths / dev proxy) |
| `VITE_USE_API` | `true` to prefer API over Excel |

When served from FastAPI, leave `VITE_API_URL` unset.

## License

Private / prototype.
