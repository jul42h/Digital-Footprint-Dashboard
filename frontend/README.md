# Digital Footprint Dashboard (Prototype)

Unified dashboard combining the **cve-dashboard-frontend** design with **Digital-Footprint-Dashboard-main** data loading.

## Data source

Loads Shodan vulnerability intelligence from `public/data/shodan_data.xlsx` via the same Excel loader pipeline as Digital-Footprint-Dashboard-main. No mock or sample data is bundled.

## Run locally

```bash
npm install
npm run dev
```

Place or replace `public/data/shodan_data.xlsx` with your Shodan export. Use **Refresh data** in the top bar to reload.

## Sections

| Route | Purpose |
|-------|---------|
| `/` | Overview — posture, trends, severity, alerts |
| `/cves` | All security issues from loaded data |
| `/ips` | Scanned IP assets |
| `/solutions` | Remediation options derived from critical/high CVEs |
| `/vendors` | Software providers aggregated from product fields |
| `/analytics` | Charts — ports, OS, services, geography |
| `/settings` | Data source info and future backend notes |

## Stack

React 18 · Vite · TypeScript · Recharts · xlsx
