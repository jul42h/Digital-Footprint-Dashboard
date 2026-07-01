import { Link } from "react-router-dom";
import type { Kpi } from "@/types";
import { SEVERITY_COLOR } from "@/lib/severity";

export function KpiCard({ kpi }: { kpi: Kpi }) {
  const color =
    kpi.tone && kpi.tone !== "neutral" ? SEVERITY_COLOR[kpi.tone] : "var(--text)";

  const content = (
    <>
      <p className="kpi-card__label">{kpi.label}</p>
      <p className="kpi-card__value" style={{ color }}>{kpi.value}</p>
      {kpi.hint && <p className="kpi-card__hint">{kpi.hint}</p>}
    </>
  );

  if (kpi.to) {
    return (
      <Link to={kpi.to} className="kpi-card kpi-card--link">
        {content}
      </Link>
    );
  }

  return <div className="kpi-card">{content}</div>;
}
