export interface AskPriorityItem {
  asset: string;
  reason: string;
}

export interface AskAiResponse {
  summary: string;
  riskScore?: number | null;
  priority: AskPriorityItem[];
  remediation: string[];
  threatIntel: string[];
  references: string[];
  intent: string;
  mode: "bedrock" | "deterministic" | "lambda";
  markdown?: string | null;
}

export interface RiskIntelligence {
  summary: string;
  riskScore: number;
  highestRiskAssets: Array<{
    asset: string;
    ip?: string;
    reason: string;
    maxCvss?: number;
    cveCount?: number;
    kevCount?: number;
  }>;
  topCriticalFindings: Array<{
    cveId?: string;
    asset?: string;
    cvss?: number;
    severity?: string;
    kev?: boolean;
    epss?: number;
    summary?: string;
  }>;
  threatIntel: string[];
  prioritizedRemediation: string[];
  references: string[];
  mode: "bedrock" | "deterministic" | "lambda";
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  structured?: AskAiResponse;
  createdAt: number;
}

export interface QuickAction {
  id: string;
  label: string;
  prompt: string;
}
