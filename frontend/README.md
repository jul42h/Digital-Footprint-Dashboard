# Digital Footprint Dashboard (Frontend)

Fresno State branded **AI Risk Intelligence** React UI. Part of the monorepo served by `footprint-api`.

See **[DASHBOARD.md](../DASHBOARD.md)** for architecture, data flow, AI intents, and what each page does.

## Data source

- **Production:** DynamoDB via `GET /api/v1/dashboard` when served from FastAPI
- **Fallback:** Empty zeroed payload when the API is unavailable (status banner shown)
- **AI:** `POST /api/cve-analysis` → FastAPI relays to the AI Risk Analyzer Lambda

## Run locally

```bash
npm install
npm run dev
```

Run `npm run api` from the repo root in another terminal for live API data.

## Routes

| Route | Purpose |
|-------|---------|
| `/` | Home command center — AI summary, risk score, signals, findings, assets, remediation |
| `/insights` | Curated AI Risk Intelligence panels (whole-footprint) |
| `/cves` | Security issues with filters and sort |
| `/threats` | Threat category guide |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation queue |
| `/vendors` | Software providers |
| `/analytics` | Extended charts |
| `/guide` | Metric & terminology reference |
| `/settings` | Theme, data source, remediation labels |

**Ask AI** is opened from the floating button (and from Home / Insights CTAs), not from the sidebar.

## Stack

React 19 · Vite · TypeScript · Recharts

## Themes

The selector offers Fresno State light/dark themes and one Valley Pride theme
(`lib/themes.ts`). Valley Pride keeps Cardinal Red and Fresno State Blue as
brand anchors, with Green V used selectively to represent the San Joaquin
Valley and its agricultural heritage.
