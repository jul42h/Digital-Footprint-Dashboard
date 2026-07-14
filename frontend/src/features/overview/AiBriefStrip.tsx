import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { analyzeCves, peekCachedAnalysis } from "@/features/ask-ai/askAiApi";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { pickPriorityCves, toBriefPreview } from "@/features/ask-ai/cveSelection";
import type { CveAnalysisResponse } from "@/features/ask-ai/types";
import { useCves } from "@/features/cves/hooks";

const HOME_BRIEF_CVE_LIMIT = 3;

/** Home strip: on-demand short but substantive brief (mode=brief). */
export function AiBriefStrip() {
  const { openWithCves } = useAskAiUi();
  const cves = useCves();
  const priority = useMemo(() => pickPriorityCves(cves, HOME_BRIEF_CVE_LIMIT), [cves]);
  const priorityIds = useMemo(() => priority.map((c) => c.id), [priority]);
  const priorityKey = priorityIds.join("|");
  const [data, setData] = useState<CveAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!priorityKey) {
      setData(null);
      setError(null);
      setLoading(false);
      setExpanded(false);
      return;
    }
    const cached = peekCachedAnalysis(priorityKey.split("|"), "brief");
    setData(cached);
    setError(null);
    setLoading(false);
    setExpanded(false);
  }, [priorityKey]);

  const runBrief = useCallback(
    async (bypassCache = false) => {
      if (!priorityIds.length || loading) return;
      setLoading(true);
      setError(null);
      setExpanded(false);
      try {
        const payload = await analyzeCves(priorityIds, {
          mode: "brief",
          bypassCache,
        });
        setData(payload);
      } catch (err: unknown) {
        setData(null);
        setError(err instanceof Error ? err.message : "Brief unavailable");
      } finally {
        setLoading(false);
      }
    },
    [priorityIds, loading],
  );

  const analyzedIds = data?.cve_ids_analyzed?.length ? data.cve_ids_analyzed : priorityIds;
  const rawSummary = data?.ai_summary?.trim() ?? "";
  const { preview, truncated } = rawSummary
    ? toBriefPreview(rawSummary)
    : { preview: "", truncated: false };
  const displayText = expanded && rawSummary ? rawSummary : preview;
  const hasBrief = Boolean(preview);
  const kevCount = priority.filter((c) => c.exploitKnown).length;

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
    <section className="ai-brief" aria-label="Priority risk brief">
      <div className="ai-brief__meta">
        <span className="ai-brief__meta-label">AI brief</span>
        <span className="ai-brief__meta-count">
          {priorityIds.length === 0
            ? "—"
            : `${priorityIds.length} CVE${priorityIds.length === 1 ? "" : "s"}`}
        </span>
        {kevCount > 0 && (
          <span className="ai-brief__meta-flag">{kevCount} KEV</span>
        )}
      </div>

      <div className="ai-brief__body">
        {loading ? (
          <p className="ai-brief__summary ai-brief__summary--skeleton" aria-live="polite">
            Writing a concise priority brief…
          </p>
        ) : (
          <p className={`ai-brief__summary${expanded ? " ai-brief__summary--full" : ""}`}>
            {priorityIds.length === 0
              ? "No issues loaded yet — refresh the dashboard when the API is connected."
              : displayText ||
                error ||
                "These are your highest-priority findings (KEV and severity first). Generate a brief for a short, actionable read — why they matter and what to do next."}
          </p>
        )}

        {hasBrief && truncated && (
          <button
            type="button"
            className="ai-brief__more"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "Show shorter" : "Show more"}
          </button>
        )}

        {priority.length > 0 && (
          <ul className="ai-brief__highlights">
            {priority.map((cve) => (
              <li key={cve.id}>
                <Link to={`/cves/${cve.id}`}>{cve.id}</Link>
                {cve.exploitKnown && <span className="ai-brief__chip-flag">KEV</span>}
                <span className="ai-brief__chip-sev">{cve.severity}</span>
              </li>
            ))}
          </ul>
        )}

        {analyzedIds.length > 0 &&
          data?.cve_ids_analyzed?.length &&
          analyzedIds.join("|") !== priorityIds.join("|") && (
            <p className="ai-brief__note">Analyzer returned a different CVE set than selected.</p>
          )}
      </div>

      <div className="ai-brief__actions">
        <button
          type="button"
          className="ai-brief__ask"
          onClick={() => void runBrief(hasBrief)}
          disabled={priorityIds.length === 0 || loading}
        >
          {loading ? "Working…" : hasBrief ? "Refresh" : "Generate brief"}
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
          onClick={() => openWithCves(priorityIds)}
          disabled={priorityIds.length === 0 || loading}
        >
          Deeper analysis
        </button>
      </div>
    </section>
  );
}
