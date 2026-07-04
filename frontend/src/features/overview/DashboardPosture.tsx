import { Link } from "react-router-dom";
import { SEVERITY_COLOR } from "@/lib/severity";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useDashboardSummary } from "./useDashboardSummary";

export function DashboardPosture() {
  const {
    exposureScore,
    exposureDelta,
    totalVulns,
    critical,
    assetsAtRisk,
    pendingRemediations,
  } = useDashboardSummary();

  const exposureLabel =
    exposureDelta === 0
      ? "Exposure"
      : `Exposure ${exposureDelta > 0 ? "+" : ""}${exposureDelta}`;

  return (
    <>
      <div className="posture-bar posture-bar--compact">
      <Link to="/solutions" className="posture-metric posture-metric--primary posture-metric--link">
        <span className="posture-metric__value" style={{ color: pendingRemediations > 0 ? SEVERITY_COLOR.high : undefined }}>
          {pendingRemediations}
        </span>
        <span className="posture-metric__label">{NAV_LABELS.fixes}</span>
      </Link>

      <Link to="/cves" className="posture-metric posture-metric--link">
        <span className="posture-metric__value" style={{ color: critical > 0 ? SEVERITY_COLOR.critical : undefined }}>
          {critical}
        </span>
        <span className="posture-metric__label">Critical</span>
      </Link>

      <Link to="/cves" className="posture-metric posture-metric--link">
        <span className="posture-metric__value">{totalVulns}</span>
        <span className="posture-metric__label">Vulnerabilities</span>
      </Link>

      <Link to="/ips" className="posture-metric posture-metric--link">
        <span className="posture-metric__value">{assetsAtRisk}</span>
        <span className="posture-metric__label">Assets at risk</span>
      </Link>

      <div className="posture-metric" title={HELP_TEXT.exposureScore}>
        <span className="posture-metric__value">{exposureScore}</span>
        <span className="posture-metric__label">{exposureLabel}</span>
      </div>
    </div>
    <p className="card-footnote card-footnote--tight">{HELP_TEXT.postureBar}</p>
    </>
  );
}
