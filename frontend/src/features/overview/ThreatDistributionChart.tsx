import { Link } from "react-router-dom";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { ViewAllLink } from "@/components/ViewAllLink";
import { THREAT_COLOR, THREAT_LABEL, THREAT_ORDER, THREAT_TECH_LABEL } from "@/lib/threats";
import { HELP_TEXT } from "@/lib/copy";
import { useThreatDistribution } from "./hooks";

export function ThreatDistributionChart() {
  const distribution = useThreatDistribution();
  const total = distribution.reduce((sum, entry) => sum + entry.count, 0);

  const rows = THREAT_ORDER.map((type) => {
    const entry = distribution.find((d) => d.type === type);
    const count = entry?.count ?? 0;
    const share = total > 0 ? Math.round((count / total) * 100) : 0;
    return {
      type,
      label: THREAT_LABEL[type],
      tech: THREAT_TECH_LABEL[type],
      count,
      share,
      color: THREAT_COLOR[type],
    };
  }).filter((row) => row.count > 0);

  return (
    <Card
      title="Threat type distribution"
      className="chart-card threat-dist-card"
      action={<ViewAllLink to="/threats" />}
    >
      <div className="chart-card__body">
        {rows.length === 0 ? (
          <p className="threat-dist__empty">No threat categories in the current dataset.</p>
        ) : (
          <div className="threat-dist">
            <div className="threat-dist__header" aria-hidden>
              <span>Category</span>
              <span>Technical</span>
              <span>Share / Count</span>
            </div>
            <ul className="threat-dist__list">
              {rows.map((row) => (
                <li key={row.type}>
                  <Link
                    to={`/threats/${row.type}`}
                    className="threat-dist__row"
                    aria-label={`${row.label}: ${row.count} issues, ${row.share}%`}
                  >
                    <span className="threat-dist__row-main">
                      <span className="threat-dist__swatch" style={{ background: row.color }} />
                      <span className="threat-dist__label">{row.label}</span>
                    </span>
                    <span className="threat-dist__tech">{row.tech}</span>
                    <span className="threat-dist__meter" aria-hidden>
                      <span
                        className="threat-dist__meter-fill"
                        style={{ width: `${row.share}%`, background: row.color }}
                      />
                    </span>
                    <span className="threat-dist__meta">
                      <span className="threat-dist__share">{row.share}%</span>
                      <span className="threat-dist__count">{row.count}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.threatDistribution}</p>
      </div>
    </Card>
  );
}

/** Index of all threat types (linked from chart footer). */
export function ThreatTypesIndexPage() {
  const distribution = useThreatDistribution();
  const total = distribution.reduce((sum, entry) => sum + entry.count, 0);

  return (
    <div className="page">
      <Link to="/" className="back-link">
        ← Overview
      </Link>
      <PageHeader
        title="Threat categories"
        subtitle="Plain-language guide to how vulnerabilities are grouped in your footprint."
      />
      <div className="threat-index">
        {THREAT_ORDER.map((type) => {
          const count = distribution.find((d) => d.type === type)?.count ?? 0;
          const share = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <Link key={type} to={`/threats/${type}`} className="threat-index__card">
              <span className="threat-index__swatch" style={{ background: THREAT_COLOR[type] }} />
              <div className="threat-index__body">
                <span className="threat-index__title">{THREAT_LABEL[type]}</span>
                <span className="threat-index__tech">{THREAT_TECH_LABEL[type]}</span>
              </div>
              <span className="threat-index__count">{count > 0 ? `${count} · ${share}%` : "—"}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
