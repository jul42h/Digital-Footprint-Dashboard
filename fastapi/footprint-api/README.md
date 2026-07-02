# Footprint API

FastAPI server for the Digital Footprint Dashboard. Reads findings from DynamoDB and serves the built React UI.

## Setup

```bash
pip3 install -r requirements.txt
export DYNAMODB_TABLE_NAME=enriched-database
export AWS_REGION=us-east-1
```

Build the frontend (one time, or after UI changes):

```bash
cd ../Documents/GitHub/Digital-Footprint-Dashboard/frontend
npm install
npm run build
```

## Run

```bash
uvicorn app:app --reload --port 8000
```

Open **http://localhost:8000** for the dashboard.

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
| `FRONTEND_DIST` | `../Documents/GitHub/Digital-Footprint-Dashboard/frontend/dist` | Path to built React app |
| `CORS_ORIGINS` | localhost dev ports | Comma-separated allowed origins |
