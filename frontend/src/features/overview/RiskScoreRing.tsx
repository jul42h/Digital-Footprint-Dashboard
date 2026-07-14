import { SEVERITY_COLOR } from "@/lib/severity";
import { useDashboardSummary } from "./useDashboardSummary";

function riskTone(score: number): string {
  if (score >= 70) return SEVERITY_COLOR.critical;
  if (score >= 40) return SEVERITY_COLOR.high;
  if (score >= 20) return SEVERITY_COLOR.medium;
  return SEVERITY_COLOR.low;
}

function riskLabel(score: number): string {
  if (score >= 70) return "Critical";
  if (score >= 40) return "Elevated";
  if (score >= 20) return "Moderate";
  return "Low";
}

/** Circular exposure score for Home. */
export function RiskScoreRing() {
  const { exposureScore, exposureDelta } = useDashboardSummary();
  const clamped = Math.max(0, Math.min(100, exposureScore));
  const tone = riskTone(clamped);
  const size = 120;
  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (clamped / 100) * c;

  return (
    <div className="risk-ring" aria-label={`Exposure score ${clamped} out of 100`}>
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
        <span className="risk-ring__label">{riskLabel(clamped)}</span>
        {exposureDelta !== 0 && (
          <span className={`risk-ring__delta${exposureDelta > 0 ? " risk-ring__delta--up" : ""}`}>
            {exposureDelta > 0 ? "+" : ""}
            {exposureDelta}
          </span>
        )}
      </div>
    </div>
  );
}
