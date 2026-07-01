# CVE Dashboard Full Stack

Digital Footprint security dashboard with a **React frontend**, **FastAPI** API, and **AWS** data layer (Lambda, DynamoDB, Athena, S3).

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   React     │────▶│  FastAPI (API    │────▶│  data-access Lambda │
│   Frontend  │     │  Gateway/Lambda) │     │  DynamoDB + Athena  │
└─────────────┘     └──────────────────┘     └─────────────────────┘
                                                      ▲
                           ┌──────────────────────────┘
                           │ S3 ingest trigger
                    ┌──────┴──────┐
                    │ ingest Lambda│
                    └─────────────┘
```

## Project structure

| Path | Description |
|------|-------------|
| `frontend/` | React dashboard (from Main-Prototype) |
| `backend/` | FastAPI app with Mangum Lambda handler |
| `lambdas/data_access/` | DynamoDB reads + Athena queries |
| `lambdas/ingest/` | S3-triggered ingest pipeline |
| `infrastructure/` | AWS SAM template |
| `scripts/` | Local snapshot + DynamoDB seeding |


## Quick start (local)

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
cp .env.example .env

# Build JSON snapshot from Excel (optional but faster)
python ../scripts/seed_dashboard.py

# Run API
uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — Vite proxies `/api` to the backend.

The frontend tries the API first, then falls back to `public/data/shodan_data.xlsx`.

### 3. Docker (API only)

```bash
docker compose up --build
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/dashboard` | Full `DashboardData` payload |
| `POST` | `/api/v1/dashboard/refresh` | Trigger refresh (Athena in AWS) |
| `GET` | `/api/v1/analytics/athena` | Athena analytics query |

## Deploy to AWS (SAM)

Prerequisites: AWS CLI, SAM CLI, Python 3.12

```bash
cd infrastructure
sam build
sam deploy --guided
```

After deploy:

1. Note the **ApiUrl** output
2. Seed DynamoDB:

```bash
python scripts/seed_dashboard.py --invoke-lambda --lambda-name cve-dashboard-data-access-dev
```

3. Set frontend env for production:

```
VITE_API_URL=https://xxxx.execute-api.us-east-1.amazonaws.com
VITE_USE_API=true
```

## Data flow

1. **Ingest**: Upload Shodan export to `s3://{RawBucket}/ingest/`
2. **Ingest Lambda** writes manifest to curated bucket, triggers refresh
3. **Data-access Lambda** queries Athena, updates DynamoDB snapshot
4. **FastAPI** invokes data-access Lambda on `GET /api/v1/dashboard`
5. **Frontend** loads via API; client-side adapters derive CVE tables, vendors, geo map

## Environment variables

### Backend (`backend/.env`)

| Variable | Local | AWS |
|----------|-------|-----|
| `ENVIRONMENT` | `local` | `aws` |
| `DATA_ACCESS_LAMBDA_NAME` | — | `cve-dashboard-data-access-dev` |
| `LOCAL_EXCEL_PATH` | `data/shodan_data.xlsx` | — |

### Frontend (`frontend/.env`)

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | API base URL (empty = dev proxy) |
| `VITE_USE_API` | `true` to prefer API over Excel |

## License

Private / prototype.
