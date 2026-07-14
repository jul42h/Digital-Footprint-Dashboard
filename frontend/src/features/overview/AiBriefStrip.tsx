import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchRiskIntelligence } from "@/features/ask-ai/askAiApi";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import type { RiskIntelligence } from "@/features/ask-ai/types";

/** Compact home brief — what matters now, without a large AI dashboard. */
export function AiBriefStrip() {
  const { setOpen, openWithPrompt } = useAskAiUi();
  const [data, setData] = useState<RiskIntelligence | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchRiskIntelligence()
      .then((payload) => {
        if (!cancelled) setData(payload);
      })
      .catch(() => {
        if (!cancelled) setData(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const topFix = data?.prioritizedRemediation?.[0];
  const topAsset = data?.highestRiskAssets?.[0];
  const topFinding = data?.topCriticalFindings?.[0];

  return (
    <section className="ai-brief" aria-label="AI risk brief">
      <div className="ai-brief__score" title="AI risk score">
        <span className="ai-brief__score-label">Risk</span>
        <span className="ai-brief__score-value">
          {loading ? "—" : (data?.riskScore ?? "—")}
        </span>
      </div>

      <div className="ai-brief__body">
        <p className="ai-brief__summary">
          {loading
            ? "Preparing analyst brief…"
            : data?.summary || "Risk brief unavailable. Start the API and refresh."}
        </p>
        {!loading && data && (
          <ul className="ai-brief__highlights">
            {topFinding?.cveId && (
              <li>
                <span>Critical</span>
                <Link to={`/cves/${topFinding.cveId}`}>{topFinding.cveId}</Link>
                {topFinding.kev ? <em>KEV</em> : null}
              </li>
            )}
            {topAsset && (
              <li>
                <span>Asset</span>
                {topAsset.ip ? (
                  <Link to={`/ips/${encodeURIComponent(topAsset.ip)}`}>{topAsset.asset}</Link>
                ) : (
                  <strong>{topAsset.asset}</strong>
                )}
              </li>
            )}
            {topFix && (
              <li>
                <span>Fix first</span>
                <button type="button" onClick={() => openWithPrompt(topFix)}>
                  {topFix.length > 72 ? `${topFix.slice(0, 72)}…` : topFix}
                </button>
              </li>
            )}
          </ul>
        )}
      </div>

      <button type="button" className="ai-brief__ask" onClick={() => setOpen(true)}>
        Ask
      </button>
    </section>
  );
}
