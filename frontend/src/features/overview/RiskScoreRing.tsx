import { useEffect, useMemo, useState } from "react";
import { peekCachedAnalysis, subscribeAnalysisCache } from "@/features/ask-ai/askAiApi";
import { DEFAULT_PRIORITY_COUNT, pickPriorityCves } from "@/features/ask-ai/cveSelection";
import { toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { MAX_FINDINGS_PER_REQUEST } from "@/features/ask-ai/types";
import { useDashboard } from "@/context/DashboardContext";
import { useCves } from "@/features/cves/hooks";
import { SEVERITY_COLOR } from "@/lib/severity";
import { riskRatingLabel } from "@/utils/summaryGenerator";
import { useDashboardSummary } from "./useDashboardSummary";

/** Tone per rating band — bands match riskRatingLabel (Lambda RISK_RATINGS). */
function riskTone(score: number): string {
  if (score >= 90) return SEVERITY_COLOR.critical;
  if (score >= 75) return SEVERITY_COLOR.high;
  if (score >= 50) return SEVERITY_COLOR.medium;
  return SEVERITY_COLOR.low;
}

/**
 * Circular risk score for Home. Prefers the computed `risk_score` from
 * the cached AI brief (same number Insights explains) and falls back to the
 * local footprint model when the brief has not loaded yet.
 */
export function RiskScoreRing() {
  const { exposureScore } = useDashboardSummary();
  const { data: dashboard } = useDashboard();
  const cves = useCves();
  const [cacheTick, setCacheTick] = useState(0);

  useEffect(() => subscribeAnalysisCache(() => setCacheTick((n) => n + 1)), []);

  const fromBrief = useMemo(() => {
    const focus = pickPriorityCves(cves, DEFAULT_PRIORITY_COUNT);
    const focusIds = focus.map((c) => c.id.toUpperCase());
    if (!focusIds.length) return null;
    const findings = toAnalysisFindingsFromData(dashboard, {
      preferCveIds: focusIds,
      limit: MAX_FINDINGS_PER_REQUEST,
    });
    return peekCachedAnalysis(focusIds, "brief", findings)?.risk_score ?? null;
    // cacheTick forces a re-read when AiBriefStrip finishes writing the brief.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cves, dashboard, cacheTick]);

  const clamped = Math.max(0, Math.min(100, fromBrief?.score ?? exposureScore));
  const tone = riskTone(clamped);
  const label = fromBrief?.rating ?? riskRatingLabel(clamped);
  const size = 120;
  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (clamped / 100) * c;

  return (
    <div className="risk-ring" aria-label={`Risk score ${clamped} out of 100`}>
      <svg className="risk-ring__svg" width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          className="risk-ring__track"
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
        />
        <circle
          className="risk-ring__value"
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={tone}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <div className="risk-ring__center">
        <span className="risk-ring__score" style={{ color: tone }}>
          {clamped}
        </span>
        <span className="risk-ring__label">{label}</span>
      </div>
    </div>
  );
}
