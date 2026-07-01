import { Link, Navigate, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { CveTable } from "@/features/cves/CveTable";
import {
  isThreatType,
  THREAT_COLOR,
  THREAT_DESCRIPTION,
  THREAT_IMPACT,
  THREAT_LABEL,
  THREAT_REMEDIATION,
  THREAT_TECH_LABEL,
} from "@/lib/threats";

export function ThreatTypePage() {
  const { type } = useParams<{ type: string }>();

  if (!type || !isThreatType(type)) {
    return <Navigate to="/" replace />;
  }

  const accent = THREAT_COLOR[type];

  return (
    <div className="page threat-page">
      <Link to="/" className="back-link">
        ← Overview
      </Link>

      <PageHeader
        eyebrow="Threat category"
        title={THREAT_LABEL[type]}
        subtitle={THREAT_TECH_LABEL[type]}
      />

      <div className="threat-page__intro">
        <span className="threat-page__accent" style={{ background: accent }} aria-hidden />
        <div className="threat-page__copy">
          <p className="threat-page__lead">{THREAT_DESCRIPTION[type]}</p>
          <p className="threat-page__impact">
            <strong>Business impact:</strong> {THREAT_IMPACT[type]}
          </p>
        </div>
      </div>

      <Card title="How to address">
        <p className="threat-page__remediation">{THREAT_REMEDIATION[type]}</p>
      </Card>

      <CveTable
        title="Related security issues"
        threatFilter={type}
        showFilter={false}
      />
    </div>
  );
}
