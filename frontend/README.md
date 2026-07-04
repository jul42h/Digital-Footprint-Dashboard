# Digital Footprint Dashboard (Frontend)

Fresno State branded React dashboard for external security posture. Part of the monorepo served by `footprint-api`.

## Data source

- **Production:** DynamoDB via `/api/v1/dashboard` when served from FastAPI
- **Fallback:** `public/data/shodan_data.xlsx` when the API is unavailable

## Run locally

```bash
npm install
npm run dev
```

Run `npm run api` from the repo root in another terminal for live API data.

## Sections

| Route | Purpose |
|-------|---------|
| `/` | Overview — posture, severity, threats, remediation |
| `/cves` | Security issues with filters and sort |
| `/threats` | Threat category guide |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation queue |
| `/vendors` | Software providers |
| `/analytics` | Extended charts |
| `/settings` | Theme and data source |

## Stack

React 19 · Vite · TypeScript · Recharts

## Themes

Fresno State (light/dark) and Valley Pride (light/dark) — switch via the top bar theme selector.
