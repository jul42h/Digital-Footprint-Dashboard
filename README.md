# Digital Footprint Dashboard

Digital Footprint dashboard for CVE tracking, CVSS scoring, affected product counts, IP threat intelligence, and threat feeds.

## Features

- **CVE Intelligence** — Recent vulnerabilities from the NVD API with CVSS scores, severity ratings, affected product counts, and expandable details
- **IP Threat Intel** — Monitored IP addresses with geolocation, ASN, ISP, threat classification, open ports, and tags
- **Dashboard Stats** — Total CVEs, critical/high counts, average CVSS, monitored IPs, and affected products
- **Charts** — Severity distribution pie chart and top CVSS bar chart

## Data Sources

| Source | Data |
|--------|------|
| [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE details, CVSS scores, affected CPEs |
| [ip-api.com](http://ip-api.com/) | IP geolocation, ISP, ASN |
| Internal threat profiles | Threat levels, tags, port observations |

## Quick Start

```bash
npm install
npm run dev
```

This starts:
- API server on `http://localhost:3001`
- Vite dev server on `http://localhost:5173`

Open **http://localhost:5173** in your browser.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start API + frontend concurrently |
| `npm run dev:client` | Frontend only |
| `npm run dev:server` | API server only |
| `npm run build` | Production build |
| `npm run preview` | Preview production build |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/dashboard` | Full dashboard payload |
| `GET /api/cves` | CVE list |
| `GET /api/ips` | IP intelligence |
| `GET /api/health` | Health check |

## Disclaimer

For authorized security research and defensive operations only. IP threat classifications use demo profiles layered on public geolocation data.
