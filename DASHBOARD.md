# Digital Footprint Dashboard — Architecture & Guide

Fresno State external security posture dashboard. The React UI reads scan findings from DynamoDB through a FastAPI backend and presents CVEs, assets, remediations, vendors, and analytics in one place.

## How it is built

```
DynamoDB (enriched-database)
        │
        ▼
footprint-api/app.py          ← scans table, caches payload
        │
        ▼
dashboard_transform.py        ← normalizes rows → DashboardData JSON
        │
        ▼
GET /api/v1/dashboard         ← single API payload for the UI
        │
        ▼
frontend services/apiLoader   ← fetch + normalize
        │
        ▼
lib/adapters.ts               ← derive views (CVEs, IPs, trends, vendors)
        │
        ▼
React pages & components      ← charts, tables, detail views
```

### Repository layout

| Path | Role |
|------|------|
| `frontend/` | React 19 + Vite + TypeScript UI |
| `frontend/dist/` | Production build (served by FastAPI; gitignored) |
| `footprint-api/` | FastAPI server, DynamoDB access, dashboard transform |
| `frontend_mount.py` | SPA static file + client-side routing helper |
| `package.json` | Root scripts: `build`, `api`, `dev` |

### Data flow

1. **Startup** — `useDashboardData` calls `loadDashboardData()` which hits `/api/v1/health`, then `/api/v1/dashboard`.
2. **Transform** — `dashboard_transform.py` maps DynamoDB finding rows into `DashboardData`: IPs, flat CVE records, aggregate stats, and scan-source counts. Pseudo-CVE IDs (`NO_CVE#…`) are filtered out.
3. **Derive** — `deriveDashboardViews()` in `frontend/src/lib/adapters.ts` builds UI-friendly structures: deduplicated CVE list, IP records, remediation solutions, vendor/product risk, alerts, and the observation panel series.
4. **Context** — `DashboardContext` exposes `data` (raw payload) and `derived` (computed views) to all pages.
5. **Refresh** — Press **R** or use the top bar refresh control. This POSTs to `/api/v1/dashboard/refresh`, re-scans DynamoDB, and reloads the payload.
6. **Fallback** — If the API is unreachable, `emptyDashboard()` returns zeroed stats so the UI still renders with a status banner.

### Remediation state (browser-local)

Remediation status labels and per-item status changes are stored in `localStorage` (`df-remediation-v1`) via `RemediationContext`. They are **not** persisted to DynamoDB yet. Configure which statuses count as “pending” under **Settings → Remediation statuses**.

---

## Pages and what each section does

### Home (`/`)

The overview summarizes posture and where to act first.

| Section | What it shows | Source |
|---------|---------------|--------|
| **Posture bar** | Pending remediations, critical count, KEV, high EPSS, at-risk assets, unique CVEs, risk score | `DashboardPosture` + `useDashboardSummary` |
| **Severity breakdown** | Donut of unique CVEs by CVSS band (critical → low) | `SeverityDonut` |
| **Observation panel** | Findings over time when multiple days/hours exist; otherwise scan sources, ports, or exploitability signals from live data | `RiskTrendChart` + `toRiskTrendView` |
| **Priority queue** | Top critical/high items ranked by KEV → EPSS → CVSS (read-only status) | `CompactRemediationQueue` |
| **Remediation progress** | Donut of solution statuses (not started, under review, in progress, done) | `RemediationProgress` |
| **Highest-risk assets** | IPs with CVEs, sortable by severity filter | `AtRiskAssets` |

Link: **What do these metrics mean?** → `/guide`

### Security issues (`/cves`, `/cves/:id`)

- **List** — All distinct CVEs with CVSS, severity, KEV/EPSS flags, affected assets, filters, and sort.
- **Detail** — Summary, scores, ports, related assets, and remediation link.

Data: `derived.cves` from `toCves()` (merged by CVE ID across hosts).

### Threat categories (`/threats`, `/threats/:type`)

- **Index** — Cards for each threat type (RCE, injection, auth, etc.) with counts.
- **Detail** — Plain-language explanation and CVEs matching that inferred category.

Categories are **inferred from CVE description text** (`lib/inferThreat.ts`), not from scanner metadata.

### IP assets (`/ips`, `/ips/:address`)

- **List** — Internet-facing hosts: hostname, location, CVE count, max CVSS, services.
- **Detail** — Ports, OS, domains, scan metadata, and linked CVEs.

Data: `derived.ips` from `toIpRecords()`.

### Remediations (`/solutions`)

Prioritized fix list for critical and high findings. **Status dropdown** on each row updates browser-local remediation state. Sorted by exploitability (KEV, EPSS, CVSS).

### Software providers (`/vendors`, `/vendors/:id`)

Vendor and product risk rollup from CVE product fields on scan records. Shows CVE counts and max CVSS per vendor/product.

### Analytics (`/analytics`)

Deeper charts not shown on the home page:

- Geographic exposure map
- CVE findings over time (by month)
- Top IPs, vulnerable ports, OS distribution
- Domain footprint, services, products, countries, avg CVSS by org

### Guide (`/guide`)

Glossary for CVE, CVSS, KEV, EPSS, dashboard metrics, remediation workflow, scan sources, and threat categories. Includes anchor links (e.g. `/guide#kev`).

### Settings (`/settings`)

- **Data source** — API endpoint, record counts, KEV/EPSS totals, last loaded timestamp
- **Remediation statuses** — Rename labels and choose which statuses count as “pending”
- **Keyboard shortcuts** — Refresh, sidebar toggle, help overlay

---

## Key frontend modules

| Module | Purpose |
|--------|---------|
| `services/dashboardLoader.ts` | Entry point for load/refresh |
| `services/apiLoader.ts` | HTTP calls to `/api/v1/*` |
| `services/emptyDashboard.ts` | Zeroed fallback payload |
| `lib/adapters.ts` | `DashboardData` → `DerivedData` (CVEs, IPs, trends, vendors) |
| `lib/exploitability.ts` | KEV/EPSS priority scoring and scan-type labels |
| `lib/severity.ts` | CVSS → severity bands and colors |
| `lib/geo.ts` | Country codes, map labels, IP location formatting |
| `utils/chartData.ts` | Bar/pie datasets for analytics and fallback panels |
| `context/RemediationContext.tsx` | Status labels + localStorage persistence |
| `context/ThemeContext.tsx` | Fresno State / Valley Pride themes |

---

## API (footprint-api)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/dashboard` | GET | Full `DashboardData` JSON for the UI |
| `/api/v1/dashboard/refresh` | POST | Re-scan DynamoDB and refresh cache |
| `/findings` | GET | Raw findings (`?ip=` optional) |
| `/findings/{ip}/{cve_id}` | GET | Single finding row |

Environment variables: see `footprint-api/README.md` (`DYNAMODB_TABLE_NAME`, `AWS_REGION`, `FRONTEND_DIST`, etc.).

---

## Running locally

```bash
# Install
cd frontend && npm install && cd ..
pip3 install -r footprint-api/requirements.txt

# Configure AWS / DynamoDB
export DYNAMODB_TABLE_NAME=enriched-database
export AWS_REGION=us-west-2

# Build + serve (recommended)
npm run api
# → http://localhost:8000
```

**Vite dev server** (hot reload on port 5173):

```bash
npm run dev          # terminal 1
npm run api:serve    # terminal 2 — or set FRONTEND_DEV_URL=http://127.0.0.1:5173
```

---

## Tech stack

- **UI:** React 19, React Router, Recharts, CSS custom properties (themes)
- **Build:** Vite, TypeScript
- **API:** FastAPI, boto3, uvicorn
- **Data:** AWS DynamoDB

---

## Extending the dashboard

1. **New DynamoDB fields** — Add parsing in `dashboard_transform.py`, extend `types/data.ts`, then surface in `adapters.ts` or the relevant page.
2. **New metric on home** — Add to `DashboardStats` in transform + `DashboardPosture` metrics array.
3. **New page** — Create feature under `frontend/src/features/`, register in `app/router.tsx`, add nav item in `layout/Sidebar.tsx` and `lib/copy.ts`.
4. **Persist remediation to server** — Replace `RemediationContext` localStorage writes with API calls when backend support exists.
