import { useCallback, useEffect, useState } from "react";
import { useCves } from "@/features/cves/hooks";
import { analyzeCves } from "./askAiApi";
import { normalizeCveId } from "./cveSelection";
import { findingsForCveIds } from "./findings";
import { sanitizeAiText } from "./sanitizeAiText";
import {
  INTENT_USER_LABEL,
  MAX_CVE_IDS_PER_REQUEST,
  type AnalysisIntent,
  type ChatMessage,
  type CveAnalysisResponse,
} from "./types";

const STORAGE_KEY = "df-cve-analysis-chat-v5";

function uid(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function loadHistory(): ChatMessage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ChatMessage[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function formatSummary(data: CveAnalysisResponse): string {
  const cleaned = sanitizeAiText(data.ai_summary);
  if (cleaned) return cleaned;
  if (data.reason?.trim()) return data.reason.trim();
  return "No summary returned.";
}

function uniqueIds(ids: string[]): string[] {
  const out: string[] = [];
  for (const id of ids) {
    const n = id.toUpperCase();
    if (n && !out.includes(n)) out.push(n);
  }
  return out.slice(0, MAX_CVE_IDS_PER_REQUEST);
}

export function useCveAnalysisChat() {
  const cves = useCves();
  const [messages, setMessages] = useState<ChatMessage[]>(() => loadHistory());
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-30)));
  }, [messages]);

  const clearChat = useCallback(() => {
    setMessages([]);
    setError(null);
    setSelectedIds([]);
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  const toggleCveId = useCallback((raw: string) => {
    const id = normalizeCveId(raw) ?? raw.toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) return;
    setSelectedIds((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= MAX_CVE_IDS_PER_REQUEST) return prev;
      return [...prev, id];
    });
  }, []);

  const setSelectedIdsCap = useCallback((ids: string[]) => {
    setSelectedIds(uniqueIds(ids));
  }, []);

  const analyze = useCallback(
    async (ids: string[], intent: AnalysisIntent) => {
      const cveIds = uniqueIds(ids);
      if (!cveIds.length || loading) return;

      setError(null);
      setLoading(true);
      setSelectedIds(cveIds);

      setMessages((prev) => [
        ...prev,
        {
          id: uid(),
          role: "user",
          content: INTENT_USER_LABEL[intent],
          cveIds,
          intent,
          createdAt: Date.now(),
        },
      ]);

      try {
        const findings = findingsForCveIds(cves, cveIds);
        const data = await analyzeCves(cveIds, {
          intent,
          findings: findings.length ? findings : undefined,
        });
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: formatSummary(data),
            cveIds: data.cve_ids_analyzed?.length ? data.cve_ids_analyzed : cveIds,
            intent,
            createdAt: Date.now(),
          },
        ]);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Analysis failed";
        setError(message);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: message,
            intent,
            createdAt: Date.now(),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [cves, loading],
  );

  return {
    messages,
    selectedIds,
    loading,
    error,
    analyze,
    clearChat,
    toggleCveId,
    setSelectedIdsCap,
  };
}
