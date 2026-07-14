/**
 * Ask AI / CVE analysis contract — keep in sync with
 * footprint-api/ask_ai/lambda_ai_risk_analyzer.py (and the deployed Lambda).
 * Do not reuse these caps outside the AI analysis path.
 */

/** UI select cap for Analyze panel (matches Lambda MAX_DETAIL_FINDINGS). */
export const MAX_CVE_IDS_PER_REQUEST = 8;
/** Findings sent for posture aggregation (API relays up to 100; Lambda max 500). */
export const MAX_FINDINGS_PER_REQUEST = 100;
/** Bare CVE ID list cap (matches Lambda MAX_CVE_IDS). */
export const MAX_CVE_IDS_PAYLOAD = 25;
/** Lambda brief detail sample size (BRIEF_TOP_FINDINGS). */
export const BRIEF_TOP_FINDINGS = 5;
/** Lambda non-brief detail sample size (MAX_DETAIL_FINDINGS). */
export const MAX_DETAIL_FINDINGS = 8;

/** Matches Lambda EPSS_NOTABLE — use only when labeling AI/posture signals. */
export const EPSS_NOTABLE = 0.5;
/** Matches Lambda EPSS_URGENT. */
export const EPSS_URGENT = 0.9;

export type AnalysisIntent = "brief" | "analyze" | "remediate" | "next_steps";
export type AnalysisMode = "brief" | "detail";

export function modeFromIntent(intent: AnalysisIntent): AnalysisMode {
  return intent === "brief" ? "brief" : "detail";
}

export function intentFromMode(mode: AnalysisMode): AnalysisIntent {
  return mode === "brief" ? "brief" : "analyze";
}

/** Intent headings required by the Lambda prompts (for structured UI rendering). */
export const REQUIRED_HEADINGS: Record<AnalysisIntent, readonly string[]> = {
  brief: ["Risk Posture", "What Stands Out", "Priority Action"],
  analyze: ["Summary", "Top Risks", "Why It Matters", "Confidence and Gaps"],
  remediate: ["Priority Order", "Recommended Actions", "Validation", "Limitations"],
  next_steps: ["Immediate", "This Week", "Owners", "Data Needed"],
};

/** Aggregate posture returned by the analyzer Lambda as `signal_summary`. */
export interface SignalSummary {
  findings_analyzed?: number;
  unique_cves?: number;
  unique_assets?: number;
  severity_breakdown?: Record<string, number>;
  kev_findings?: number;
  kev_cves?: string[];
  epss_findings_scored?: number;
  epss_at_or_above_0_5?: number;
  max_epss?: number | null;
  verified_true?: number;
  verified_false?: number;
  verified_unknown?: number;
  top_services?: Array<{ value: string; findings: number }>;
  top_products?: Array<{ value: string; findings: number }>;
  assets_with_most_findings?: Array<{ value: string; findings: number }>;
  [key: string]: unknown;
}

export interface CveAnalysisResponse {
  status: string;
  statusCode?: number | null;
  invocation_source?: string | null;
  reason?: string | null;
  error?: string | null;
  cve_ids_analyzed: string[];
  total_valid_cve_ids?: number | null;
  total_findings_provided?: number | null;
  total_findings_analyzed?: number | null;
  total_findings_skipped?: number | null;
  findings_detailed?: number | null;
  max_findings?: number | null;
  signal_summary?: SignalSummary | null;
  ai_summary?: string | null;
  mode?: AnalysisMode | string | null;
  intent?: AnalysisIntent | string | null;
}

/** Structured finding fields the Lambda accepts (subset of FINDING_FIELDS). */
export interface AnalysisFinding {
  cve_id: string;
  ip?: string;
  primary_ip?: string;
  cvss?: string;
  epss?: string;
  ranking_epss?: string;
  kev?: boolean | string;
  verified?: boolean | string;
  summary?: string;
  port?: string;
  protocol?: string;
  transport?: string;
  service_name?: string;
  product?: string;
  version?: string;
  domains?: string;
  hostnames?: string;
  os?: string;
  [key: string]: string | boolean | undefined;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  cveIds?: string[];
  intent?: AnalysisIntent;
  createdAt: number;
}

/** Panel actions — map 1:1 to Lambda intents (home uses `brief` separately). */
export const ANALYZE_PRESETS: Array<{
  id: Exclude<AnalysisIntent, "brief">;
  label: string;
  hint: string;
}> = [
  { id: "analyze", label: "Risk", hint: "Summary · Top Risks · Why It Matters" },
  { id: "remediate", label: "Fix", hint: "Priority Order · Recommended Actions" },
  { id: "next_steps", label: "Next", hint: "Immediate · This Week · Owners" },
];

export const INTENT_USER_LABEL: Record<AnalysisIntent, string> = {
  brief: "Brief",
  analyze: "Risk analysis",
  remediate: "Remediation",
  next_steps: "Next steps",
};
