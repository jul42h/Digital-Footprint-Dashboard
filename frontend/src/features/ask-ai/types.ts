/**
 * Ask AI / CVE analysis contract — keep in sync with
 * footprint-api/ask_ai/lambda_ai_risk_analyzer.py (and the deployed Lambda).
 * Do not reuse these caps outside the AI analysis path.
 */

/** UI select cap for the "Analyze findings" tab (matches Lambda MAX_DETAIL_FINDINGS). */
export const MAX_CVE_IDS_PER_REQUEST = 10;
/** Findings sent for posture aggregation (API relays up to 100; Lambda max 1500). */
export const MAX_FINDINGS_PER_REQUEST = 100;
/** Bare CVE ID list cap (matches Lambda MAX_CVE_IDS). */
export const MAX_CVE_IDS_PAYLOAD = 25;
/** Lambda detail sample size for every intent (MAX_DETAIL_FINDINGS). */
export const MAX_DETAIL_FINDINGS = 10;
/** Longest question the ask_ai intent accepts (Lambda MAX_QUESTION_CHARS). */
export const MAX_QUESTION_LENGTH = 500;

/** Matches Lambda EPSS_NOTABLE — use only when labeling AI/posture signals. */
export const EPSS_NOTABLE = 0.5;
/** Matches Lambda EPSS_URGENT. */
export const EPSS_URGENT = 0.9;

/** One intent per dashboard surface — mirrors Lambda INTENTS exactly. */
export type AnalysisIntent =
  | "brief"
  | "insights"
  | "risk_score"
  | "threat_intel"
  | "critical_findings"
  | "risk_assets"
  | "remediate"
  | "ask_ai";

export type AnalysisMode = "brief" | "detail";

/** How `ai_summary` is formatted — one prose paragraph, or Markdown `###` sections. */
export type AiSummaryFormat = "prose" | "sections";

/** Matches Lambda OUTPUT_SHAPES. Prose intents have no REQUIRED_HEADINGS entry. */
export const OUTPUT_SHAPES: Record<AnalysisIntent, AiSummaryFormat> = {
  brief: "prose",
  insights: "sections",
  risk_score: "prose",
  threat_intel: "sections",
  critical_findings: "sections",
  risk_assets: "sections",
  remediate: "sections",
  ask_ai: "prose",
};

export function modeFromIntent(intent: AnalysisIntent): AnalysisMode {
  return intent === "brief" ? "brief" : "detail";
}

/** Legacy `mode` only distinguishes brief vs. detail; "insights" is the Lambda's
 * own default for any unrecognized/absent non-brief intent. */
export function intentFromMode(mode: AnalysisMode): AnalysisIntent {
  return mode === "brief" ? "brief" : "insights";
}

/** Headings required for sectioned intents (matches Lambda REQUIRED_HEADINGS).
 * Prose intents (brief, risk_score, ask_ai) have no heading contract — they are
 * validated by word count instead; see MIN_PROSE_WORDS. */
export const REQUIRED_HEADINGS: Partial<Record<AnalysisIntent, readonly string[]>> = {
  insights: ["Insights", "Confidence and Gaps"],
  threat_intel: ["Known Exploitation", "Attacker Interest", "Exposed Technology", "Evidence Gaps"],
  critical_findings: ["Critical Findings", "Business Impact", "Next Action"],
  risk_assets: ["Highest-Risk Assets", "Why They Rank", "Next Action"],
  remediate: ["Priority Order", "Recommended Actions", "Owners", "Validation", "Limitations"],
};

/** Word floor for prose intents (matches Lambda MIN_PROSE_WORDS). */
export const MIN_PROSE_WORDS: Partial<Record<AnalysisIntent, number>> = {
  brief: 40,
  risk_score: 25,
  ask_ai: 8,
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
  // Optional Pipeline 4 context — zero/empty means "not supplied", not "none".
  internet_exposed_findings?: number;
  internet_exposure_known?: boolean;
  asset_criticality_breakdown?: Array<{ value: string; findings: number }>;
  top_business_units?: Array<{ value: string; findings: number }>;
  top_owner_teams?: Array<{ value: string; findings: number }>;
  exploit_maturity_breakdown?: Array<{ value: string; findings: number }>;
  named_threats?: Array<{ value: string; findings: number }>;
  [key: string]: unknown;
}

/** Evidence-backed contributor to the risk score (Lambda `_build_risk_score`). */
export interface RiskScoreDriver {
  driver: "exploitation" | "severity" | "exposure" | string;
  score: number;
  weight: number;
  evidence: string;
}

/** Computed by the Lambda from posture, not by the model — the same findings
 * always produce the same score. Present on any response that analyzed findings,
 * regardless of intent. */
export interface RiskScoreResult {
  score: number;
  rating: "critical" | "high" | "elevated" | "moderate" | "low" | string;
  confidence: "high" | "moderate" | "low" | string;
  confidence_notes: string[];
  drivers: RiskScoreDriver[];
  method?: string | null;
}

export interface CveAnalysisResponse {
  status: string;
  statusCode?: number | null;
  invocation_source?: string | null;
  reason?: string | null;
  error?: string | null;
  question?: string | null;
  cve_ids_analyzed: string[];
  total_valid_cve_ids?: number | null;
  total_findings_provided?: number | null;
  total_findings_analyzed?: number | null;
  total_findings_skipped?: number | null;
  findings_detailed?: number | null;
  max_findings?: number | null;
  signal_summary?: SignalSummary | null;
  ai_summary?: string | null;
  ai_summary_format?: AiSummaryFormat | string | null;
  risk_score?: RiskScoreResult | null;
  model_used?: string | null;
  model_routing?: Record<string, unknown> | null;
  mode?: AnalysisMode | string | null;
  intent?: AnalysisIntent | string | null;
}

/** Structured finding fields the Lambda accepts (subset of FINDING_FIELDS),
 * including optional Pipeline 4 business/threat context (PIPELINE4_FIELDS).
 * Every Pipeline 4 field is optional and copied only when present upstream —
 * none of it flows through dashboard_transform.py yet (see the TODO there). */
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
  // Pipeline 4 (optional; TODO(pipeline-4) — names are an open assumption).
  asset_criticality?: string;
  business_unit?: string;
  owner_team?: string;
  environment?: string;
  internet_exposed?: boolean | string;
  exploit_maturity?: string;
  threat_actors?: string;
  malware?: string;
  campaigns?: string;
  remediation_status?: string;
  first_seen?: string;
  last_seen?: string;
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

/**
 * Panel actions — map 1:1 to Lambda intents for the CVE-select "Analyze findings" tab.
 * `brief` / `insights` / `risk_score` / `threat_intel` / `critical_findings` /
 * `risk_assets` are whole-system views driven by the /insights page (not a CVE
 * selection); `ask_ai` is the panel's free-text tab. `remediate` is the only
 * intent that makes sense scoped to a hand-picked set of findings.
 */
export const ANALYZE_PRESETS: Array<{
  id: Extract<AnalysisIntent, "insights" | "remediate">;
  label: string;
  hint: string;
}> = [
  { id: "insights", label: "Insights", hint: "Insights · Confidence and Gaps" },
  { id: "remediate", label: "Remediate", hint: "Priority Order · Recommended Actions" },
];

export const INTENT_USER_LABEL: Record<AnalysisIntent, string> = {
  brief: "AI summary",
  insights: "AI Insights",
  risk_score: "Risk score",
  threat_intel: "Threat intelligence",
  critical_findings: "Top critical findings",
  risk_assets: "Highest-risk assets",
  remediate: "Remediation",
  ask_ai: "Ask AI",
};
