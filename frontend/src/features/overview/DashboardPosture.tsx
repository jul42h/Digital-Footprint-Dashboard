import { Link } from "react-router-dom";
import { HELP_TEXT } from "@/lib/copy";
import { SEVERITY_COLOR } from "@/lib/severity";
import { useDashboard } from "@/context/DashboardContext";
import { useDashboardSummary } from "./useDashboardSummary";

/**
 * Home KPI strip — aligned with nav destinations.
 * Exposure score is shown in the ring below (not repeated here).
 */
export function DashboardPosture() {
  const { data } = useDashboard();
  const { critical, assetsAtRisk, pendingRemediations } = useDashboardSummary();

  const metrics = [
    {
      key: "critical",
      to: "/cves",
      value: critical,
      label: "Critical issues",
      tone: critical > 0 ? SEVERITY_COLOR.critical : undefined,
    },
    {
      key: "kev",
      to: "/cves",
      value: data.stats.kevFindings,
      label: "Known exploited",
      tone: data.stats.kevFindings > 0 ? SEVERITY_COLOR.high : undefined,
    },
    {
      key: "fixes",
      to: "/solutions",
      value: pendingRemediations,
      label: "Pending remediations",
      tone: pendingRemediations > 0 ? SEVERITY_COLOR.high : undefined,
    },
    {
      key: "assets",
      to: "/ips",
      value: assetsAtRisk,
      label: "At-risk assets",
    },
  ];

  return (
    <div
      className="posture-bar posture-bar--overview posture-bar--home-business"
      role="list"
      aria-label={HELP_TEXT.postureBar}
    >
      {metrics.map((metric) => {
        const content = (
          <>
            <span
              className="posture-metric__value"
              style={metric.tone ? { color: metric.tone } : undefined}
            >
              {metric.value}
            </span>
            <span className="posture-metric__label">{metric.label}</span>
          </>
        );

        const className = ["posture-metric", metric.to ? "posture-metric--link" : ""]
          .filter(Boolean)
          .join(" ");

        if (metric.to) {
          return (
            <Link key={metric.key} to={metric.to} className={className} role="listitem">
              {content}
            </Link>
          );
        }

        return (
          <div key={metric.key} className={className} role="listitem">
            {content}
          </div>
        );
      })}
    </div>
  );
}
