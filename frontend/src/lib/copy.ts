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
  ipRange: "IP range",
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
    "Risk intelligence command center — what matters most, why it matters, and what to fix first.",
  postureBar:
    "Key counts from the latest scan. Select a metric to open the related list.",
  exposureScore:
    "Overall risk from 0–100, weighted by known exploitation, severity mix, and asset spread.",
  riskScoreHome:
    "Overall risk from 0–100 based on exploitation, severity, and exposure.",
  prioritySignals: "Exploitability signals you can act on or ask about right away.",
  aiBrief: "Plain-language summary of posture, main risks, and the most important next step.",
  topCriticalFindings: "Highest-priority findings that drive the summary above.",
  fixFirst: "What to fix first, ranked by known exploitation and severity.",
  atRiskAssets: "Hosts carrying the most risk right now.",
  insightsPage:
    "Curated risk intelligence for the whole footprint — insights, score, threat context, findings, assets, and remediation.",
  aiInsightsSection: "Actionable conclusions: what matters, why, and what to do.",
  riskScoreSection:
    "A 0–100 score with the evidence behind it — exploitation, severity, and exposure.",
  threatIntelSection:
    "Exploitation and exposure signals from your scanned data only — no external threat feeds.",
  criticalFindingsSection: "Findings that need attention first, with impact and next action.",
  riskAssetsSection: "Which assets carry the most risk and why.",
  remediateSection: "What to fix first, concrete actions, and how to confirm.",
  askAiPage:
    "Ask specific questions, look up a CVE, or get remediation for selected findings.",
  homeNextActions: "Jump to deeper intelligence, ask a question, or start remediating.",
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
