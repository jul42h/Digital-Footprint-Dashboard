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
  activelyTargeted: "Known exploited",
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

/** Short explanations under page headers and key sections. */
export const HELP_TEXT = {
  homePage:
    "Snapshot of exposure, priority signals, and where to act first across your external footprint.",
  postureBar:
    "Key counts from the latest scan. Select a metric to open the related list.",
  exposureScore: "Overall footprint risk from 0–100. Higher means greater exposure.",
  severityDonut: "Unique CVEs grouped by CVSS severity.",
  prioritySignals: "Exploitability and urgency cues you can act on immediately.",
  aiBrief: "AI summary of the top five highest-risk findings in context of the full set.",
  fixFirst: "Highest-priority remediations, ranked by known exploitation and severity.",
  atRiskAssets: "Internet-facing hosts with open vulnerabilities, ordered by highest CVSS.",
  geoMap:
    "Asset locations from Shodan geodata. City coordinates when available; otherwise country center.",
  geoMapEmpty: "No location data available for vulnerable assets in this dataset.",
  geoMapUnlocated: (count: number) =>
    `${count} vulnerable asset${count === 1 ? "" : "s"} could not be placed on the map.`,
  dataUnavailable:
    "Dashboard data could not be loaded. Start footprint-api and press Refresh (R).",
  dataEmpty:
    "The API responded with no findings. Check DynamoDB connectivity and table contents.",
  cvesPage:
    "CVEs on your external footprint, ranked by risk. Filter by severity, transport, or known exploitation.",
  ipsPage:
    "Internet-facing hosts observed for your organization, with services and vulnerability counts.",
  solutionsPage:
    "Prioritized actions for critical and high findings. Update status on each row to track progress.",
  vendorsPage:
    "Software providers and products tied to vulnerable services in your environment.",
  threatsPage:
    "How findings are grouped by vulnerability pattern (inferred from CVE descriptions).",
  analyticsPage:
    "Geography, ports, operating systems, and services — patterns across the footprint.",
  settingsPage: "Data source, refresh, and remediation status labels.",
  guidePage: "Definitions for CVE, CVSS, KEV, EPSS, remediation statuses, and dashboard terms.",
  loading: "Loading your security footprint…",
} as const;
