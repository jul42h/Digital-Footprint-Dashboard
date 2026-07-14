import { Link } from "react-router-dom";
import { SEVERITY_COLOR } from "@/lib/severity";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { useDashboardSummary } from "./useDashboardSummary";

export function DashboardPosture() {
  const { data } = useDashboard();
  const {
    exposureScore,
    exposureDelta,
    critical,
    assetsAtRisk,
    pendingRemediations,
  } = useDashboardSummary();

  const exposureLabel =
    exposureDelta === 0 ? "Risk score" : `Δ ${exposureDelta > 0 ? "+" : ""}${exposureDelta}`;

  const metrics = [
    {
      key: "score",
      value: exposureScore,
      label: exposureLabel,
      title: HELP_TEXT.exposureScore,
      primary: true,
    },
    {
      key: "critical",
      to: "/cves",
      value: critical,
      label: "Critical",
      tone: critical > 0 ? SEVERITY_COLOR.critical : undefined,
    },
    {
      key: "kev",
      to: "/cves",
      value: data.stats.kevFindings,
      label: "KEV",
      tone: data.stats.kevFindings > 0 ? SEVERITY_COLOR.high : undefined,
    },
    {
      key: "fixes",
      to: "/solutions",
      value: pendingRemediations,
      label: NAV_LABELS.fixes,
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
    <div className="posture-bar posture-bar--overview posture-bar--compact-home" role="list">
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

        const className = [
          "posture-metric",
          metric.primary ? "posture-metric--primary" : "",
          metric.to ? "posture-metric--link" : "",
        ]
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
          <div key={metric.key} className={className} title={metric.title} role="listitem">
            {content}
          </div>
        );
      })}
    </div>
  );
}
