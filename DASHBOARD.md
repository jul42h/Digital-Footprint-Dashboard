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

## Data: ingestion, utilization, and calculations

This section describes where findings come from, how they are loaded into the app, and every major calculation the dashboard performs to produce the numbers you see.

### 1. Source of truth — DynamoDB

| Setting | Default | Purpose |
|---------|---------|---------|
| `DYNAMODB_TABLE_NAME` | `enriched-database` | Table scanned by the API |
| `AWS_REGION` | `us-west-2` | AWS region for boto3 |

Each **row** in the table is a finding record — typically one IP + CVE combination (or a host discovery row without a CVE). Rows are produced upstream by Shodan and related scan pipelines (CVE imports, DNS discovery, XML scans, etc.) and written to DynamoDB with fields such as:

| DynamoDB field (examples) | Used for |
|---------------------------|----------|
| `ip`, `cve_id` | Primary keys; grouping by host |
| `cvss`, `cve_score`, `score` | CVSS numeric score |
| `cvss_severity`, `severity` | Severity label (or derived from score) |
| `summary`, `description` | CVE text, threat inference |
| `observed_at`, `timestamp`, `processed_at` | Observation timestamps |
| `kev`, `known_exploited` | CISA Known Exploited Vulnerabilities flag |
| `epss`, `ranking_epss` | Exploit Prediction Scoring System |
| `verified` | Shodan-verified exposure |
| `port`, `ports`, `open_ports` | Affected / open ports |
| `product`, `service_name` | Software product and service |
| `org`, `location_country_code`, `location_city` | Organization and geolocation |
| `hostnames`, `domains`, `os` | Host identity and OS |
| `scan_type` | Scan pipeline source (e.g. Shodan CVE import) |

Rows with pseudo-CVE IDs matching `NO_CVE#…` are **dropped** — they are not real CVE identifiers.

### 2. How data is pulled (backend)

```
Browser  →  GET /api/v1/dashboard  →  load_dashboard()
                                              │
                                              ▼
                                    scan_all()  (full DynamoDB table scan)
                                              │
                                              ▼
                                    findings_to_dashboard(items)
                                              │
                                              ▼
                                    JSON cached in memory (_dashboard_cache)
```

**Pull mechanism** (`footprint-api/app.py`):

- `scan_all()` paginates through the entire DynamoDB table with `table.scan()` until `LastEvaluatedKey` is exhausted.
- `load_dashboard()` transforms all rows once and stores the result in an in-memory cache.
- `GET /api/v1/dashboard` returns the cached payload (fast repeat loads).
- `POST /api/v1/dashboard/refresh` sets `force_refresh=True`, re-scans DynamoDB, rebuilds the payload, and updates the cache.

**Raw access** (not used by the main UI, but available):

- `GET /findings` — all raw rows, or `?ip=` for one host
- `GET /findings/{ip}/{cve_id}` — single row

The React app does **not** query DynamoDB directly. It only talks to the FastAPI endpoints above.

### 3. Backend transform (`dashboard_transform.py`)

`findings_to_dashboard()` converts raw rows into the `DashboardData` JSON shape:

#### Step A — Group rows by IP

Each DynamoDB row is merged into an `ips[]` entry via `_merge_ip_record()`:

- Lists (ports, services, products, hostnames, domains, etc.) are **unioned** across rows for the same IP.
- CVEs on the same IP are deduplicated by CVE ID (latest row wins for that ID).
- `riskLevel` on each IP = highest severity among its CVEs.

#### Step B — Build CVE objects (`_build_cve`)

For each row with a valid `CVE-YYYY-NNNN` ID:

| Output field | Source |
|--------------|--------|
| `score` | `cvss`, `cve_score`, or `score` |
| `severity` | `cvss_severity` / `severity`, or computed from score |
| `publishedDate` | `observed_at`, `published_date`, `timestamp`, etc. (ISO UTC) |
| `kev` | Boolean from `kev` / `known_exploited` |
| `epss` | Float; omitted if zero |
| `verified` | Boolean from `verified` |
| `product`, `service`, `port` | From row fields |

**Severity from CVSS score** (backend, same bands as frontend):

| CVSS | Band |
|------|------|
| ≥ 9.0 | Critical |
| ≥ 7.0 | High |
| ≥ 4.0 | Medium |
| ≥ 0.1 | Low |
| else | Informational |

#### Step C — Flatten CVE records

`cveRecords[]` is one entry per **CVE instance** (CVE + IP + port context). The UI uses this for tables, charts, and per-finding detail without re-walking nested IP structures.

#### Step D — Aggregate stats (`_compute_stats`)

Computed **server-side** and sent in `stats`:

| Stat | Calculation |
|------|-------------|
| `totalIPs` | Count of distinct IPs after grouping |
| `totalCVEs` | Total CVE **instances** across all hosts (same CVE on 3 hosts = 3) |
| `uniqueCVEs` | Distinct CVE IDs |
| `criticalCVEs` … `informationalCVEs` | Instance counts per severity band |
| `averageCVSS` | Mean of scores where score > 0 |
| `highestCVSS` | Max score |
| `newestVulnerability` / `oldestVulnerability` | Min/max of `publishedDate` among CVEs |
| `uniqueOrganizations` / `uniqueCountries` | Distinct org/country on IP records |
| `vulnerableIPs` | IPs with ≥ 1 CVE |
| `discoveredHosts` | IPs with services, ports, or hostnames |
| `discoveryOnlyHosts` | Discovered hosts with **no** CVEs |
| `kevFindings` | CVE instances where `kev` is true |
| `highEpssFindings` | CVE instances where `epss ≥ 0.1` (10%) |
| `verifiedFindings` | CVE instances where `verified` is true |

#### Step E — Scan source counts

`scanSourceCounts` tallies raw rows by `scan_type` (e.g. how many records came from each pipeline).

#### API payload shape

```json
{
  "ips": [ /* grouped host records with nested cves[] */ ],
  "stats": { /* aggregates above */ },
  "cveRecords": [ /* flat CVE+IP rows */ ],
  "scanSourceCounts": { "scan_type_name": count },
  "lastUpdated": "ISO timestamp when transform ran",
  "source": "dynamodb"
}
```

### 4. How the frontend loads data

| Step | File | What happens |
|------|------|--------------|
| 1 | `hooks/useDashboardData.ts` | On mount, calls `loadDashboardData()` |
| 2 | `services/dashboardLoader.ts` | Checks API health; on failure returns `emptyDashboard()` |
| 3 | `services/apiLoader.ts` | `fetch('/api/v1/dashboard')`, merges defaults into `stats` |
| 4 | `lib/adapters.ts` | `deriveDashboardViews(data)` builds all UI views |
| 5 | `context/DashboardContext.tsx` | Provides `data` + `derived` to every page |

Refresh (`R` key or top bar): `POST /api/v1/dashboard/refresh` → reload `GET /api/v1/dashboard`.

### 5. Frontend derivation (`lib/adapters.ts`)

The API payload is further transformed **in the browser** for display:

| Derived view | Function | What it does |
|--------------|----------|--------------|
| `cves` | `toCves()` | Merges `cveRecords` by CVE ID across hosts; keeps max CVSS, union of ports/assets, KEV/EPSS flags |
| `ips` | `toIpRecords()` | Sorts hosts by max CVSS; adds `criticalCount`, `highCount`, `cveCount` per IP |
| `solutions` | `toSolutions()` | One remediation item per **critical/high** CVE; default status `triage` if KEV else `open` |
| `alerts` | `toAlerts()` | Top 12 CVEs that are KEV, high EPSS (≥10%), or critical |
| `riskTrendView` | `toRiskTrendView()` | Observation timeline or snapshot fallback (see below) |
| `vendors` / `products` | `toVendorsAndProducts()` | Groups by product string; vendor = first token of product name |

### 6. Calculations performed in the UI

These are **not** pre-computed by the API — they run in the frontend from `data` or `derived`:

#### Network risk score (0–100)

`utils/summaryGenerator.ts` → `computeNetworkRiskScore(stats)`:

```
weighted = critical×10 + high×7 + medium×4 + low×2 + informational×0.5
raw      = (weighted / totalCVEs) × (averageCVSS / 10) × 10
score    = min(100, round(raw, 1))
```

Shown in the home posture bar and Analytics KPI strip.

#### Exploitability priority score

`lib/exploitability.ts` → `exploitabilityScore(cve)` — used to sort the priority queue and remediation list:

```
base = cvss × 10
+ 100 if KEV (exploitKnown)
+ 50  if epss ≥ 0.5
+ 25  if epss ≥ 0.1
+ 10  if epss > 0
+ 15  if verified
```

Higher score = higher priority.

#### Severity bands (UI)

`lib/severity.ts` → `cvssToSeverity(cvss)` — same thresholds as the backend (9 / 7 / 4 / 0). Used for badges, donuts, and filters when re-deriving from a numeric score.

#### Home posture metrics (`useDashboardSummary`)

| Metric | Calculation |
|--------|-------------|
| **Pending remediations** | Solutions whose status is in the configured “pending” set (default: not started + under review) |
| **Critical** | Count of unique CVEs with UI severity `critical` |
| **KEV / High EPSS** | From `data.stats.kevFindings` and `data.stats.highEpssFindings` (server-computed instance counts) |
| **At-risk assets** | IPs where `criticalCount > 0` |
| **Unique CVEs** | `data.stats.uniqueCVEs` |
| **Risk score** | `computeNetworkRiskScore` (above) |
| **Exposure delta** | Last day minus previous day on the observation timeline (only when ≥2 days of data) |

#### Severity donut

Counts **unique CVEs** (`derived.cves`) per UI severity band — not instance counts.

#### Observation panel (`toRiskTrendView`)

Uses `cve.publishedDate` (observation timestamp from DynamoDB, not CVE publish date):

1. **≥2 calendar days** → area chart, findings per day (last 14 days)
2. **1 day, ≥2 distinct hours** → area chart, findings per hour
3. **Single snapshot** → fallback bar chart, in order:
   - Scan sources (`scanSourceCounts`)
   - Findings by port (top 8 from `cveRecords`)
   - Exploitability signals (KEV, high EPSS, verified, critical counts from `stats`)

#### Threat categories

`lib/inferThreat.ts` matches CVE **summary text** against keyword rules (RCE, injection, auth, etc.). Default category if no match: `misconfiguration`. Counts on `/threats` are per unique CVE after inference.

#### Vendor risk score

`toVendorsAndProducts()`:

```
vendor.riskScore = min(100, round(maxCvssAcrossVendorProducts × 10))
```

Vendor name is the first word/token of the product string (heuristic, not a separate DynamoDB vendor field).

#### Analytics charts (`utils/chartData.ts`)

Built on demand from `data`:

- **CVEs over time** — bucket `cveRecords` by month of `publishedDate`
- **Top IPs** — sort `ips` by CVE count on each host
- **Port heatmap** — count `cveRecords` per port
- **OS / services / products / countries** — frequency counts from IP and record fields
- **Avg CVSS by org** — mean score per `organization` on flat records
- **Domain footprint** — domains on IPs, weighted by CVE count per host

#### Remediation progress donut

Counts solutions by status. **Pending** center value uses the same pending-status filter as the posture bar. Status values come from `RemediationContext` (browser `localStorage`), overlaid on API-derived solution list.

### 7. What is not from DynamoDB

| Data | Storage |
|------|---------|
| Remediation status per item | Browser `localStorage` (`df-remediation-v1`) |
| Remediation status labels / pending config | Browser `localStorage` |
| Theme preference | Browser `localStorage` |
| Empty fallback when API is down | Generated client-side (`emptyDashboard()`) |

### 8. End-to-end utilization map

| UI element | Primary data source |
|------------|---------------------|
| Posture bar counts | `stats` + `derived.cves` + `derived.ips` + remediation context |
| Severity donut | `derived.cves` (unique, by severity) |
| Observation panel | `cveRecords` timestamps / `scanSourceCounts` / `stats` |
| Priority queue | `derived.solutions` sorted by `exploitabilityScore` |
| At-risk assets table | `derived.ips` sorted by `maxCvss` |
| CVE list/detail | `derived.cves` |
| IP list/detail | `derived.ips` + nested CVE data from `data.ips` |
| Remediations table | `derived.solutions` + local status overrides |
| Vendors | `derived.vendors` / `derived.products` |
| Analytics charts | `data` via `buildChartData` / `buildAnalyticsData` |
| Geo map | `derived.ips` with country/city coordinates |
| Settings record counts | `data.stats` + `data.source` |

---

## Pages and what each section does

### Home (`/`)

The overview summarizes posture and where to act first.

| Section | What it shows | Source |
|---------|---------------|--------|
| **Posture bar** | Pending remediations, critical count, KEV, high EPSS, at-risk assets, unique CVEs, risk score | `DashboardPosture` + `useDashboardSummary` |
| **AI priority brief** | Short executive takeaway for top CVEs (`mode=brief`) | `AiBriefStrip` → `POST /api/cve-analysis` |
| **Severity breakdown** | Donut of unique CVEs by CVSS band (critical → low) | `SeverityDonut` |
| **Observation panel** | Findings over time when multiple days/hours exist; otherwise scan sources, ports, or exploitability signals from live data | `RiskTrendChart` + `toRiskTrendView` |
| **Priority queue** | Top critical/high items ranked by KEV → EPSS → CVSS (read-only status) | `CompactRemediationQueue` |
| **Remediation progress** | Donut of solution statuses (not started, under review, in progress, done) | `RemediationProgress` |
| **Highest-risk assets** | IPs with CVEs, sortable by severity filter | `AtRiskAssets` |

Link: **What do these metrics mean?** → `/guide` · floating **Analyze** panel for deep dives

### Security issues (`/cves`, `/cves/:id`)

- **List** — All distinct CVEs with CVSS, severity, KEV/EPSS flags, affected assets, filters, and sort.
- **Detail** — Summary, scores, ports, related assets, **Analyst notes** (`mode=detail` via `/api/cve-analysis`), and remediations.

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

### Risk analysis (floating Analyze panel)

CVE-centric AI analysis — not free-text chat.

- Select up to 5 CVE IDs (priority chips or paste); history in `localStorage`
- Calls `POST /api/cve-analysis` with `{ cve_ids, mode: "detail" }`
- Home brief uses the same endpoint with `mode: "brief"` and a short preview
- FastAPI relays to the **AI Risk Analyzer** Lambda (no Bedrock call from the API process)

Legacy route `/ask` still opens the panel and redirects home.

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
| `/api/cve-analysis` | POST | AI summary for 1–5 CVE IDs (`mode`: `brief` \| `detail`) via Lambda |
| `/findings` | GET | Raw findings (`?ip=` optional) |
| `/findings/{ip}/{cve_id}` | GET | Single finding row |

Environment variables: see `footprint-api/README.md` (`DYNAMODB_TABLE_NAME`, `AWS_REGION`, `CVE_ANALYZER_*`, `FRONTEND_DIST`, etc.).

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
- **Data:** AWS DynamoDB (primary); AI summaries via Lambda (`ai-risk-analyzer`)

---

## Extending the dashboard

1. **New DynamoDB fields** — Add parsing in `dashboard_transform.py`, extend `types/data.ts`, then surface in `adapters.ts` or the relevant page.
2. **New metric on home** — Add to `DashboardStats` in transform + `DashboardPosture` metrics array.
3. **New page** — Create feature under `frontend/src/features/`, register in `app/router.tsx`, add nav item in `layout/Sidebar.tsx` and `lib/copy.ts`.
4. **Persist remediation to server** — Replace `RemediationContext` localStorage writes with API calls when backend support exists.
