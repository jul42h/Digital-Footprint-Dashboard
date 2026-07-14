import { apiUrl } from "@/lib/api";
import type { AskAiResponse, RiskIntelligence } from "./types";

export interface AskAiPayload {
  question: string;
  history?: Array<{ role: "user" | "assistant"; content: string }>;
  cve_id?: string;
  host?: string;
}

export async function postAskAi(payload: AskAiPayload): Promise<AskAiResponse> {
  const response = await fetch(apiUrl("/api/v1/ask"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Ask AI failed (${response.status})`);
  }
  return (await response.json()) as AskAiResponse;
}

export async function fetchRiskIntelligence(): Promise<RiskIntelligence> {
  const response = await fetch(apiUrl("/api/v1/risk-intelligence"));
  if (!response.ok) {
    throw new Error(`Risk intelligence failed (${response.status})`);
  }
  return (await response.json()) as RiskIntelligence;
}
