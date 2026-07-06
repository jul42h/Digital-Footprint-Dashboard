# Digital Footprint Dashboard (Frontend)

Fresno State branded React dashboard for external security posture. Part of the monorepo served by `footprint-api`.

See **[DASHBOARD.md](../DASHBOARD.md)** for architecture, data flow, and what each page/section does.

## Data source

- **Production:** DynamoDB via `GET /api/v1/dashboard` when served from FastAPI
- **Fallback:** Empty zeroed payload when the API is unavailable (status banner shown)

## Run locally

```bash
npm install
npm run dev
```

Run `npm run api` from the repo root in another terminal for live API data.

## Routes

| Route | Purpose |
|-------|---------|
| `/` | Overview — posture, severity, observation panel, remediation |
| `/cves` | Security issues with filters and sort |
| `/threats` | Threat category guide |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation queue |
| `/vendors` | Software providers |
| `/analytics` | Extended charts |
| `/guide` | Metric & terminology reference |
| `/settings` | Theme, data source, remediation labels |

## Stack

React 19 · Vite · TypeScript · Recharts

## Themes

Fresno State (light/dark) and Valley Pride (light/dark) — switch via the top bar theme selector.
