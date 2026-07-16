import { useCallback, useEffect, useState } from "react";
import { useDashboard } from "@/context/DashboardContext";
import { useCves } from "@/features/cves/hooks";
import { analyzeCves, askAi } from "./askAiApi";
import { normalizeCveId } from "./cveSelection";
import { findingsForCveIds, toAnalysisFindingsFromData } from "./findings";
import { sanitizeAiText } from "./sanitizeAiText";
import {
  INTENT_USER_LABEL,
  MAX_CVE_IDS_PER_REQUEST,
  MAX_FINDINGS_PER_REQUEST,
  MAX_QUESTION_LENGTH,
  type AnalysisIntent,
  type ChatMessage,
  type CveAnalysisResponse,
} from "./types";

const STORAGE_KEY = "df-cve-analysis-chat-v6";

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
  const { data: dashboard } = useDashboard();
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
        const fromRecords = toAnalysisFindingsFromData(dashboard, {
          onlyCveIds: cveIds,
          preferCveIds: cveIds,
          limit: MAX_FINDINGS_PER_REQUEST,
        });
        const findings = fromRecords.length ? fromRecords : findingsForCveIds(cves, cveIds);
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
    [cves, dashboard, loading],
  );

  const ask = useCallback(
    async (
      question: string,
      options?: {
        focusCveIds?: string[];
        displayLabel?: string;
        questionId?: string;
        questionParams?: Record<string, string>;
      },
    ) => {
      const trimmed = question.trim().slice(0, MAX_QUESTION_LENGTH);
      const questionId = options?.questionId?.trim();
      if ((!trimmed && !questionId) || loading) return;

      setError(null);
      setLoading(true);

      const focus = uniqueIds(options?.focusCveIds ?? []);
      const display = options?.displayLabel ?? (trimmed || questionId || "Ask AI");

      setMessages((prev) => [
        ...prev,
        {
          id: uid(),
          role: "user",
          // Callers like lookupCve / guided chips may send a question_id for the
          // Lambda while showing a short label in the transcript.
          content: display,
          cveIds: focus.length ? focus : undefined,
          intent: "ask_ai",
          createdAt: Date.now(),
        },
      ]);

      try {
        const findings = toAnalysisFindingsFromData(dashboard, {
          preferCveIds: focus.length ? focus : undefined,
          onlyCveIds: focus.length ? focus : undefined,
          limit: MAX_FINDINGS_PER_REQUEST,
        });
        // If focusing a CVE that somehow has no rows, fall back to whole sample
        // so the model can still say the data does not include it.
        const payloadFindings =
          findings.length > 0
            ? findings
            : toAnalysisFindingsFromData(dashboard, { limit: MAX_FINDINGS_PER_REQUEST });

        const data = await askAi(trimmed, {
          findings: payloadFindings.length ? payloadFindings : undefined,
          cveIds: focus.length ? focus : undefined,
          questionId,
          questionParams: options?.questionParams,
        });
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: formatSummary(data),
            cveIds: focus.length ? focus : data.cve_ids_analyzed,
            intent: "ask_ai",
            createdAt: Date.now(),
          },
        ]);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Ask AI failed";
        setError(message);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: message,
            intent: "ask_ai",
            createdAt: Date.now(),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [dashboard, loading],
  );

  /**
   * Look up a typed CVE ID in the loaded footprint. Missing IDs get a local
   * answer — no model call — so analysts are not charged for empty lookups.
   */
  const lookupCve = useCallback(
    async (raw: string) => {
      if (loading) return;

      const id = normalizeCveId(raw);
      if (!id) {
        // "CVE-YYYY-NNNNN", not a real ID like "CVE-2024-12345" — chat messages
        // auto-link anything matching the CVE pattern, which would otherwise
        // turn this format example into a dead-end link to a CVE that (almost
        // certainly) isn't in the loaded footprint.
        const message =
          "Enter a CVE ID like CVE-YYYY-NNNNN. Letters, year, and number are all required.";
        setError(message);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "user",
            content: raw.trim() || "CVE lookup",
            intent: "ask_ai",
            createdAt: Date.now(),
          },
          {
            id: uid(),
            role: "assistant",
            content: message,
            intent: "ask_ai",
            createdAt: Date.now(),
          },
        ]);
        return;
      }

      const match = cves.find((c) => c.id.toUpperCase() === id);
      if (!match) {
        const message = `${id} is not in the current footprint data. It may be outside the scanned set, filtered out, or not yet loaded — try Refresh (R) or search Security issues.`;
        setError(null);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "user",
            content: id,
            cveIds: [id],
            intent: "ask_ai",
            createdAt: Date.now(),
          },
          {
            id: uid(),
            role: "assistant",
            content: message,
            cveIds: [id],
            intent: "ask_ai",
            createdAt: Date.now(),
          },
        ]);
        return;
      }

      setSelectedIdsCap([id]);
      await ask("", {
        focusCveIds: [id],
        displayLabel: id,
        questionId: "cve-lookup",
        questionParams: { cve_id: id },
      });
    },
    [ask, cves, loading, setSelectedIdsCap],
  );

  return {
    messages,
    selectedIds,
    loading,
    error,
    analyze,
    ask,
    lookupCve,
    clearChat,
    toggleCveId,
    setSelectedIdsCap,
  };
}
