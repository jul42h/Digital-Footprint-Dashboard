import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { THREAT_COLOR, THREAT_LABEL, THREAT_ORDER, THREAT_TECH_LABEL } from "@/lib/threats";
import { useThreatDistribution } from "@/features/overview/hooks";

export function ThreatTypesPage() {
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
