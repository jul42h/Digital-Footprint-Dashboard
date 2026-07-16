export const APP_NAME = "Digital Footprint";
export const APP_TAGLINE = "Fresno State";

export const NAV_LABELS = {
  home: "Home",
  insights: "AI Risk Intelligence",
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
    "Snapshot of exposure, priority signals, and where to act.",
  postureBar:
    "Key counts from the latest scan. Select a metric to open the related list.",
  exposureScore:
    "Whole-footprint risk from 0–100, weighted by known exploitation, severity mix, and asset spread — the same model behind the AI risk score.",
  prioritySignals: "Exploitability and urgency cues you can act on immediately.",
  aiBrief: "Whole-system AI summary of overall posture, main risks, and the most important next step.",
  topCriticalFindings: "The highest-risk findings behind the AI summary above.",
  fixFirst: "Highest-priority remediations, ranked by known exploitation and severity.",
  atRiskAssets: "Internet-facing hosts with open vulnerabilities, ordered by highest CVSS.",
  insightsPage:
    "Whole-system AI summary, prioritized insights, an explainable risk score, and threat intelligence — grounded only in your scanned data.",
  aiSummarySection:
    "One paragraph on overall posture, main risks, affected areas, and the most important next step — not a CVE list.",
  aiInsightsSection:
    "The most impactful, actionable findings, each with why it matters, risk level, and a recommended action.",
  riskScoreSection:
    "A pipeline-computed 0–100 score with the evidence behind it — exploitation, severity, and exposure.",
  threatIntelSection:
    "Exploitation and exposure signals from your own data only — this dashboard has no external threat-feed access.",
  criticalFindingsSection:
    "The individual findings needing attention first, with business impact and next action.",
  riskAssetsSection:
    "Which assets carry the most risk and why, ranked by evidence rather than finding count alone.",
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
