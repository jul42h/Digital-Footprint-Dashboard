import { Link, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { SolutionTable } from "@/features/solutions/SolutionTable";
import { LABELS, NAV_LABELS } from "@/lib/copy";
import { useCve } from "./hooks";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-row">
      <span className="detail-row__label">{label}</span>
      <span className="detail-row__value">{children}</span>
    </div>
  );
}

export function CveDetailPage() {
  const { id = "" } = useParams();
  const cve = useCve(id);

  return (
    <div className="page" style={{ maxWidth: 760 }}>
      <Link to="/cves" className="back-link">
        ← Back to {NAV_LABELS.issues.toLowerCase()}
      </Link>

      {!cve ? (
        <Card>We could not find that issue.</Card>
      ) : (
        <Card
          title={cve.id}
          action={cve.exploitKnown ? <SeverityBadge severity="critical" /> : undefined}
        >
          <p className="issue-summary">{cve.summary}</p>

          <Row label="Severity">
            <SeverityBadge severity={cve.severity} />
          </Row>
          <Row label={LABELS.riskScore}>
            <CvssScore score={cve.cvss} />
          </Row>
          <Row label={LABELS.system}>
            <span className="mono">{cve.asset}</span>
          </Row>
          <Row label={LABELS.networkPorts}>
            <span className="mono">{cve.ports.join(", ")} ({cve.transport})</span>
          </Row>
          <Row label={LABELS.activelyTargeted}>
            {cve.exploitKnown ? "Yes — known exploited vulnerability (KEV)" : "No known active exploitation"}
          </Row>
          {cve.epss != null && (
            <Row label="EPSS score">
              {(cve.epss * 100).toFixed(2)}% probability of exploitation in 30 days
            </Row>
          )}
          {cve.verified && (
            <Row label="Verified exposure">
              Yes — confirmed by Shodan scan metadata
            </Row>
          )}
          {cve.affectedAssets && cve.affectedAssets.length > 1 && (
            <Row label="Affected assets">
              <span className="mono">{cve.affectedAssets.join(", ")}</span>
            </Row>
          )}
          <Row label={LABELS.published}>
            {new Date(cve.publishedAt).toLocaleDateString(undefined, {
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          </Row>
        </Card>
      )}

      {cve && (
        <SolutionTable
          cveId={cve.id}
          title="Remediations"
          showFilter={false}
        />
      )}
    </div>
  );
}
