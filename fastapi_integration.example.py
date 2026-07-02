"""
Mount the built React dashboard in your existing FastAPI app.

1. Build the frontend once:
     cd frontend && npm install && npm run build

2. Copy the mount_frontend() call into your FastAPI main module.
   Register all API routes BEFORE calling mount_frontend().

3. Restart uvicorn and open http://localhost:8000
"""

from fastapi import FastAPI

from frontend_mount import mount_frontend


# --- Example usage in your app --------------------------------------------

app = FastAPI()


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.get("/api/v1/dashboard")
def dashboard():
    # Return your DashboardData JSON payload here.
    return {}


@app.get("/findings")
def findings(ip: str | None = None):
    return {"count": 0, "items": []}


mount_frontend(app)
