import { useCallback, useEffect, useState } from "react";
import { analyzeCves } from "./askAiApi";
import { extractCveIds, normalizeCveId } from "./cveSelection";
import {
  MAX_CVE_IDS_PER_REQUEST,
  type AnalysisMode,
  type ChatMessage,
  type CveAnalysisResponse,
} from "./types";

const STORAGE_KEY = "df-cve-analysis-chat-v1";

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
  if (data.ai_summary?.trim()) return data.ai_summary.trim();
  if (data.reason?.trim()) return data.reason.trim();
  return "Analysis completed with no summary returned.";
}

export function useCveAnalysisChat() {
  const [messages, setMessages] = useState<ChatMessage[]>(() => loadHistory());
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-40)));
  }, [messages]);

  const clearChat = useCallback(() => {
    setMessages([]);
    setError(null);
    setInput("");
    setSelectedIds([]);
    // Keep analysis session cache so home brief / detail reuse still works.
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  const addCveId = useCallback((raw: string) => {
    const id = normalizeCveId(raw);
    if (!id) return false;
    setSelectedIds((prev) => {
      if (prev.includes(id) || prev.length >= MAX_CVE_IDS_PER_REQUEST) return prev;
      return [...prev, id];
    });
    return true;
  }, []);

  const removeCveId = useCallback((id: string) => {
    setSelectedIds((prev) => prev.filter((x) => x !== id));
  }, []);

  const setPendingIds = useCallback((ids: string[]) => {
    setSelectedIds(ids.slice(0, MAX_CVE_IDS_PER_REQUEST));
  }, []);

  const analyze = useCallback(
    async (ids?: string[], mode: AnalysisMode = "detail") => {
      const fromInput = extractCveIds(input);
      const merged = [...(ids ?? selectedIds), ...fromInput];
      const unique: string[] = [];
      for (const id of merged) {
        const normalized = id.toUpperCase();
        if (!unique.includes(normalized)) unique.push(normalized);
      }
      const cveIds = unique.slice(0, MAX_CVE_IDS_PER_REQUEST);
      if (!cveIds.length || loading) return;

      setError(null);
      setLoading(true);
      setInput("");
      setSelectedIds(cveIds);

      const userMsg: ChatMessage = {
        id: uid(),
        role: "user",
        content:
          mode === "detail"
            ? `Deep dive: ${cveIds.join(", ")}`
            : `Brief: ${cveIds.join(", ")}`,
        cveIds,
        mode,
        createdAt: Date.now(),
      };
      setMessages((prev) => [...prev, userMsg]);

      try {
        // Cache hit returns immediately (sessionStorage / memory) — still one code path.
        const data = await analyzeCves(cveIds, { mode });
        const assistantMsg: ChatMessage = {
          id: uid(),
          role: "assistant",
          content: formatSummary(data),
          cveIds: data.cve_ids_analyzed?.length ? data.cve_ids_analyzed : cveIds,
          mode,
          createdAt: Date.now(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } catch (err) {
        const message = err instanceof Error ? err.message : "CVE analysis failed";
        setError(message);
        setMessages((prev) => [
          ...prev,
          {
            id: uid(),
            role: "assistant",
            content: `I could not complete that analysis. ${message}`,
            createdAt: Date.now(),
          },
        ]);
      } finally {
        setLoading(false);
      }
    },
    [input, loading, selectedIds],
  );

  return {
    messages,
    selectedIds,
    input,
    setInput,
    loading,
    error,
    analyze,
    clearChat,
    addCveId,
    removeCveId,
    setPendingIds,
  };
}
