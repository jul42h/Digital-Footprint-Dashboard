export const APP_NAME = "Digital Footprint";
export const APP_TAGLINE = "Fresno State · Cybersecurity";

export const NAV_LABELS = {
  home: "Home",
  issues: "Security issues",
  threats: "Threat categories",
  systems: "IP assets",
  fixes: "Remediations",
  providers: "Software providers",
  analytics: "Analytics",
  guide: "Guide",
  settings: "Settings",
} as const;

export const LABELS = {
  riskScore: "Risk score",
  issueId: "Issue ID",
  issues: "Issues",
  vulns: "Vulnerabilities",
  services: "Services",
  lastScan: "Last scan",
  severity: "Severity",
  systems: "Systems",
  summary: "What we found",
  hostname: "System name",
  ipAddress: "Network address",
  viewAll: "View all",
  learnMore: "See details",
  activelyTargeted: "Actively targeted online",
  published: "Reported on",
  networkPorts: "Network ports",
  system: "Affected system",
  vendorFix: "Official fix available",
  effort: "Effort to fix",
  status: "Status",
  provider: "Provider",
  software: "Software",
  version: "Version",
  riskLevel: "Risk level",
  remediations: "Remediations",
  vulnerabilities: "Vulnerabilities",
  location: "Location",
} as const;

/** Short explanations shown under section headers and charts. */
export const HELP_TEXT = {
  postureBar:
    "Summary counts from your latest scan. Click a metric to jump to that section. Exposure score is 0–100 (higher means more risk).",
  exposureScore:
    "Combined risk score from severity mix and average CVSS across all findings. Higher is worse.",
  exposureTrend:
    "Findings grouped by observation day from scan timestamps. Switches to hourly or snapshot breakdowns when the dataset spans a single window.",
  severityDonut: "Unique CVEs grouped by CVSS severity band.",
  threatDistribution: "Categories inferred from CVE descriptions — not from scan metadata.",
  geoMap:
    "Locations come from Shodan geolocation on each scanned IP. City coordinates are used when available; otherwise the country center is shown.",
  geoMapEmpty:
    "No country or city data was available for vulnerable assets in this dataset.",
  geoMapUnlocated: (count: number) =>
    `${count} vulnerable asset${count === 1 ? "" : "s"} could not be placed on the map (missing location data).`,
  topIps: "Internet-facing addresses with the most CVE findings in your footprint.",
  scanSources: "Where observations originated — Shodan CVE imports, DNS discovery, and XML scans.",
  exploitabilityStrip:
    "Prioritization signals from DynamoDB: CISA KEV catalog matches, high EPSS scores, and Shodan-verified exposures.",
  domainFootprint: "Domains linked to scanned hosts, weighted by CVE findings on each asset.",
  dataUnavailable:
    "Dashboard data could not be loaded from the API. Start footprint-api and press Refresh (R).",
  dataEmpty:
    "The API responded but no findings were returned. Check DynamoDB connectivity and table contents.",
  priorityQueue:
    "Highest-priority critical and high findings (KEV and EPSS ranked). Status is read-only here — change it on the Remediations page.",
  remediationProgress: "Status of recommended fixes for critical and high severity issues.",
  atRiskAssets: "Scanned systems with open vulnerabilities, ordered by highest CVSS.",
  cvesPage:
    "CVEs discovered on your external footprint, ranked by risk. Use filters to narrow by severity, transport, or known exploitation.",
  ipsPage:
    "Internet-facing hosts Shodan observed for your organization, with services and vulnerability counts per address.",
  solutionsPage:
    "Prioritized actions for critical and high findings. Track progress from not started through completion.",
  vendorsPage:
    "Software vendors and products tied to vulnerable services in your environment.",
  analyticsPage:
    "Extended charts for geography, ports, operating systems, and services — useful for spotting patterns across the footprint.",
  settingsPage:
    "Where dashboard data is loaded from and how to refresh it.",
  guidePage:
    "Definitions for CVE, CVSS, KEV, EPSS, remediation statuses, and other dashboard terminology.",
  loading: "Loading your security footprint…",
} as const;
