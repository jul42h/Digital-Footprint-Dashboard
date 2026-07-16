import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { analyzeCves, peekCachedAnalysis } from "@/features/ask-ai/askAiApi";
import {
  MIN_PROSE_WORDS,
  OUTPUT_SHAPES,
  REQUIRED_HEADINGS,
  type AnalysisFinding,
  type AnalysisIntent,
  type CveAnalysisResponse,
} from "@/features/ask-ai/types";

export type SectionIntent = Extract<
  AnalysisIntent,
  | "brief"
  | "insights"
  | "risk_score"
  | "threat_intel"
  | "critical_findings"
  | "risk_assets"
  | "remediate"
>;

const NOT_DEPLOYED_MESSAGE =
  "This section isn't available yet — it needs the latest AI service deployed.";

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countHeadings(intent: SectionIntent, text: string): number {
  const headings = REQUIRED_HEADINGS[intent] ?? [];
  return headings.filter((heading) =>
    new RegExp(`^#{1,4}\\s*${escapeRegExp(heading)}\\b`, "im").test(text),
  ).length;
}

/**
 * A deployed Lambda that predates an intent doesn't error — it silently falls
 * back to "insights" for anything it doesn't recognize (see `_resolve_intent_mode`
 * in lambda_ai_risk_analyzer.py). Detect that mismatch here rather than
 * rendering an "insights"-shaped answer under, say, the "Risk score" heading.
 */
function matchesIntent(intent: SectionIntent, data: CveAnalysisResponse): boolean {
  if (data.intent && data.intent !== intent) return false;

  // The Risk Score card pairs the prose rationale with the computed
  // score object — both must be present, not just wordy-enough prose.
  if (intent === "risk_score" && typeof data.risk_score?.score !== "number") {
    return false;
  }

  const text = data.ai_summary ?? "";
  const shape = OUTPUT_SHAPES[intent];

  if (shape === "prose") {
    const words = text.trim().split(/\s+/).filter(Boolean).length;
    return words >= (MIN_PROSE_WORDS[intent] ?? 20);
  }

  const headings = REQUIRED_HEADINGS[intent] ?? [];
  return countHeadings(intent, text) >= Math.min(2, headings.length);
}

/**
 * Fetch-on-mount + cache + loading/error state for a whole-system AI section
 * (no CVE selection). Mirrors the pattern AiBriefStrip uses for the home brief,
 * shared here so Insights / Risk Score / Threat Intel / Critical Findings /
 * Highest-Risk Assets / Remediation don't each hand-roll it.
 */
export function useAiSection(intent: SectionIntent, findings: AnalysisFinding[]) {
  const findingsKey = useMemo(() => findings.map((f) => f.cve_id).join("|"), [findings]);
  const [data, setData] = useState<CveAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const findingsRef = useRef(findings);
  findingsRef.current = findings;

  const accept = useCallback(
    (payload: CveAnalysisResponse) => {
      if (!matchesIntent(intent, payload)) {
        setData(null);
        setError(NOT_DEPLOYED_MESSAGE);
        return;
      }
      setData(payload);
      setError(null);
    },
    [intent],
  );

  const run = useCallback(
    async (bypassCache: boolean) => {
      const current = findingsRef.current;
      if (!current.length || inFlight.current) return;
      inFlight.current = true;
      setLoading(true);
      setError(null);
      try {
        const payload = await analyzeCves([], { intent, findings: current, bypassCache });
        accept(payload);
      } catch (err) {
        setData(null);
        setError(err instanceof Error ? err.message : `${intent} unavailable`);
      } finally {
        setLoading(false);
        inFlight.current = false;
      }
    },
    // findingsKey stands in for `findings` so this only changes on real content change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [intent, findingsKey, accept],
  );

  useEffect(() => {
    if (!findingsKey) {
      setData(null);
      setError(null);
      return;
    }
    const cached = peekCachedAnalysis([], intent, findingsRef.current);
    if (cached) {
      accept(cached);
      return;
    }
    void run(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingsKey, intent]);

  return { data, loading, error, refresh: () => void run(true) };
}
