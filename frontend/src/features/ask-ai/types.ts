export const MAX_CVE_IDS_PER_REQUEST = 5;

/** Home strip = brief; Analyze panel + CVE detail = detail. */
export type AnalysisMode = "brief" | "detail";

export interface CveAnalysisResponse {
  status: string;
  invocation_source?: string | null;
  reason?: string | null;
  cve_ids_analyzed: string[];
  total_valid_cve_ids?: number | null;
  ai_summary?: string | null;
  mode?: AnalysisMode | string | null;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  cveIds?: string[];
  mode?: AnalysisMode;
  createdAt: number;
}
