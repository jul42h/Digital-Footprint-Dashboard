import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  analyzeCves,
  briefSignalKey,
  peekCachedAnalysis,
  rememberBriefSignal,
  shouldAutoRefreshBrief,
} from "@/features/ask-ai/askAiApi";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { DEFAULT_PRIORITY_COUNT, pickPriorityCves } from "@/features/ask-ai/cveSelection";
import { toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { sanitizeAiText } from "@/features/ask-ai/sanitizeAiText";
import { MAX_FINDINGS_PER_REQUEST, type CveAnalysisResponse } from "@/features/ask-ai/types";
import { useDashboard } from "@/context/DashboardContext";
import { useCves } from "@/features/cves/hooks";
import { AiBriefMarkdown, briefHasMoreSections } from "./AiBriefMarkdown";

/** Findings sent for whole-system posture; the "brief" intent describes the full
 * analyzed set, not just the highest-risk sample. */
const HOME_BRIEF_POSTURE_LIMIT = MAX_FINDINGS_PER_REQUEST;

function formatAge(ageMs: number): string {
  if (ageMs < 60_000) return "just now";
  const mins = Math.round(ageMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  return `${hrs}h ago`;
}

/** Whole-system AI summary (Lambda intent "brief"). */
export function AiBriefStrip({ variant = "default" }: { variant?: "default" | "business" }) {
  const business = variant === "business";
  const { openWithCves } = useAskAiUi();
  const { data: dashboard } = useDashboard();
  const cves = useCves();

  /** Top findings named as examples and used as the cache-invalidation signal —
   * the brief itself now describes the whole analyzed set, not just these. */
  const briefFocus = useMemo(
    () => pickPriorityCves(cves, DEFAULT_PRIORITY_COUNT),
    [cves],
  );

  const focusIds = useMemo(() => briefFocus.map((c) => c.id.toUpperCase()), [briefFocus]);
  const focusKey = useMemo(() => focusIds.join("|"), [focusIds]);
  const signalKey = useMemo(() => briefSignalKey(briefFocus), [briefFocus]);

  /** Instance findings for Lambda posture (focus CVE rows first, then wider set). */
  const postureFindings = useMemo(
    () =>
      toAnalysisFindingsFromData(dashboard, {
        preferCveIds: focusIds,
        limit: HOME_BRIEF_POSTURE_LIMIT,
      }),
    [dashboard, focusIds],
  );

  const [data, setData] = useState<CveAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [ageMs, setAgeMs] = useState<number | null>(null);
  const inFlight = useRef(false);
  const signalRef = useRef(signalKey);
  signalRef.current = signalKey;

  const runBrief = useCallback(
    async (bypassCache: boolean) => {
      if (!focusIds.length || inFlight.current) return;
      inFlight.current = true;
      setLoading(true);
      setError(null);
      setExpanded(false);
      try {
        const payload = await analyzeCves(focusIds, {
          intent: "brief",
          findings: postureFindings.length ? postureFindings : undefined,
          bypassCache,
        });
        rememberBriefSignal(focusIds, signalRef.current);
        setData(payload);
        setAgeMs(0);
      } catch (err: unknown) {
        setData(null);
        setError(err instanceof Error ? err.message : "Brief unavailable");
      } finally {
        setLoading(false);
        inFlight.current = false;
      }
    },
    [focusIds, postureFindings],
  );

  useEffect(() => {
    if (!focusKey) {
      setData(null);
      setError(null);
      setLoading(false);
      setExpanded(false);
      setAgeMs(null);
      return;
    }

    const decision = shouldAutoRefreshBrief(focusIds, signalKey);

    if (!decision.refresh) {
      const cached = peekCachedAnalysis(focusIds, "brief");
      if (cached) {
        setData(cached);
        setAgeMs(decision.ageMs);
        setError(null);
        setExpanded(false);
        return;
      }
    } else {
      const cached = peekCachedAnalysis(focusIds, "brief");
      if (cached) {
        setData(cached);
        setAgeMs(decision.ageMs);
      }
    }

    void runBrief(true);
  }, [focusKey, focusIds, signalKey, runBrief]);

  const rawSummary = sanitizeAiText(data?.ai_summary);
  const hasBrief = Boolean(rawSummary);
  const canExpand = hasBrief && briefHasMoreSections(rawSummary, 1);

  const focusCount = briefFocus.length;
  const setSize =
    data?.total_findings_analyzed ??
    data?.signal_summary?.findings_analyzed ??
    postureFindings.length;

  const scopeLine = (() => {
    if (!focusCount) return null;
    const parts = [`${setSize} finding${setSize === 1 ? "" : "s"} analyzed`];
    if (data?.signal_summary?.unique_assets != null) {
      const n = data.signal_summary.unique_assets;
      parts.push(`${n} asset${n === 1 ? "" : "s"}`);
    }
    if (data?.risk_score) {
      parts.push(`Risk score ${data.risk_score.score} (${data.risk_score.rating})`);
    }
    if (hasBrief && ageMs != null) {
      parts.push(`Updated ${formatAge(ageMs)}`);
    }
    return parts.join(" · ");
  })();

  const copyBrief = async () => {
    if (!rawSummary) return;
    try {
      await navigator.clipboard.writeText(rawSummary);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* ignore */
    }
  };

  return (
    <section
      className={`ai-brief${business ? " ai-brief--business" : ""}`}
      aria-label="AI brief"
    >
      {!business && (
        <div className="ai-brief__meta">
          <span className="ai-brief__meta-label">AI summary</span>
          <span className="ai-brief__meta-count">
            {setSize === 0 ? "—" : `${setSize} finding${setSize === 1 ? "" : "s"}`}
          </span>
        </div>
      )}

      <div className="ai-brief__body">
        {business && scopeLine && <p className="ai-brief__scope">{scopeLine}</p>}

        {loading && !hasBrief ? (
          <p className="ai-brief__summary ai-brief__summary--skeleton" aria-live="polite">
            Generating brief…
          </p>
        ) : focusCount === 0 ? (
          <p className="ai-brief__summary">No findings loaded yet.</p>
        ) : hasBrief ? (
          <>
            <AiBriefMarkdown content={rawSummary} collapsed={!expanded} maxCollapsedSections={1} />
            {canExpand && (
              <button
                type="button"
                className="ai-brief__more"
                onClick={() => setExpanded((v) => !v)}
              >
                {expanded ? "Show less" : "Show full brief"}
              </button>
            )}
          </>
        ) : (
          <p className="ai-brief__summary">
            {error || "Brief unavailable — try Refresh."}
          </p>
        )}
      </div>

      <div className="ai-brief__actions">
        <button
          type="button"
          className="ai-brief__ask"
          onClick={() => void runBrief(true)}
          disabled={focusCount === 0 || loading}
        >
          {loading ? "…" : "Refresh"}
        </button>
        {hasBrief && (
          <button
            type="button"
            className="ai-brief__ask ai-brief__ask--secondary"
            onClick={() => void copyBrief()}
            disabled={loading}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        )}
        <button
          type="button"
          className="ai-brief__ask ai-brief__ask--secondary"
          onClick={() => openWithCves(focusIds)}
          disabled={focusCount === 0 || loading}
        >
          Analyze
        </button>
      </div>
    </section>
  );
}
