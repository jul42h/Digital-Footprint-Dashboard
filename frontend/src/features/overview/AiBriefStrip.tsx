import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  analyzeCves,
  briefSignalKey,
  peekCachedAnalysis,
  rememberBriefSignal,
  shouldAutoRefreshBrief,
} from "@/features/ask-ai/askAiApi";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { pickPriorityCves } from "@/features/ask-ai/cveSelection";
import { toAnalysisFindings } from "@/features/ask-ai/findings";
import { sanitizeAiText } from "@/features/ask-ai/sanitizeAiText";
import {
  BRIEF_TOP_FINDINGS,
  MAX_FINDINGS_PER_REQUEST,
  type CveAnalysisResponse,
} from "@/features/ask-ai/types";
import { useCves } from "@/features/cves/hooks";
import { AiBriefMarkdown, briefHasMoreSections } from "./AiBriefMarkdown";

/** Extra findings for posture context; Lambda briefs only the top BRIEF_TOP_FINDINGS. */
const HOME_BRIEF_POSTURE_LIMIT = MAX_FINDINGS_PER_REQUEST;

function formatAge(ageMs: number): string {
  if (ageMs < 60_000) return "just now";
  const mins = Math.round(ageMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  return `${hrs}h ago`;
}

/** Home AI brief scoped to the Lambda brief sample (top 5). */
export function AiBriefStrip({ variant = "default" }: { variant?: "default" | "business" }) {
  const business = variant === "business";
  const { openWithCves } = useAskAiUi();
  const cves = useCves();

  /** Exact set the brief narrative is about (≤5). */
  const briefFocus = useMemo(
    () => pickPriorityCves(cves, BRIEF_TOP_FINDINGS),
    [cves],
  );
  /** Wider set for posture_summary so the top 5 are placed in context. */
  const posturePool = useMemo(
    () => pickPriorityCves(cves, HOME_BRIEF_POSTURE_LIMIT),
    [cves],
  );

  const focusIds = useMemo(() => briefFocus.map((c) => c.id.toUpperCase()), [briefFocus]);
  const focusKey = useMemo(() => focusIds.join("|"), [focusIds]);
  const signalKey = useMemo(() => briefSignalKey(briefFocus), [briefFocus]);

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
        // Put focus findings first; Lambda re-ranks but this keeps identity clear.
        const focusKeys = new Set(focusIds);
        const ordered = [
          ...briefFocus,
          ...posturePool.filter((c) => !focusKeys.has(c.id.toUpperCase())),
        ];
        const payload = await analyzeCves(focusIds, {
          intent: "brief",
          findings: toAnalysisFindings(ordered, HOME_BRIEF_POSTURE_LIMIT),
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
    [briefFocus, focusIds, posturePool],
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
  const briefedCount = Math.min(
    BRIEF_TOP_FINDINGS,
    data?.findings_detailed ?? focusCount,
  );
  const setSize =
    data?.total_findings_analyzed ?? data?.signal_summary?.findings_analyzed ?? posturePool.length;

  const scopeLine = (() => {
    if (!focusCount) return null;
    const top =
      focusCount < BRIEF_TOP_FINDINGS
        ? `All ${focusCount} available finding${focusCount === 1 ? "" : "s"}`
        : `Top ${BRIEF_TOP_FINDINGS} highest-risk findings`;
    const parts = [top];
    if (setSize > BRIEF_TOP_FINDINGS) {
      parts.push(`${setSize} in set`);
    }
    if (data?.signal_summary?.unique_assets != null) {
      const n = data.signal_summary.unique_assets;
      parts.push(`${n} asset${n === 1 ? "" : "s"}`);
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
          <span className="ai-brief__meta-label">AI brief</span>
          <span className="ai-brief__meta-count">
            {focusCount === 0 ? "—" : `Top ${briefedCount}`}
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
