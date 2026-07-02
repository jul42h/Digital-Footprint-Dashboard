import { Link, useNavigate, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { LABELS, NAV_LABELS } from "@/lib/copy";
import { useCve } from "@/features/cves/hooks";
import { useIp } from "./hooks";

export function IpDetailPage() {
  const { address = "" } = useParams();
  const decoded = decodeURIComponent(address);
  const ip = useIp(decoded);
  const navigate = useNavigate();

  return (
    <div className="page" style={{ maxWidth: 760 }}>
      <Link to="/ips" className="back-link">
        ← Back to {NAV_LABELS.systems.toLowerCase()}
      </Link>

      {!ip ? (
        <Card>We could not find that network address.</Card>
      ) : (
        <>
          <Card title={ip.address}>
            <div className="detail-inline">
              <div>
                <span className="detail-inline__label">{LABELS.hostname} </span>
                <span>{ip.hostname}</span>
              </div>
              {(ip.city || ip.country) && (
                <div>
                  <span className="detail-inline__label">{LABELS.location} </span>
                  <span>{[ip.city, ip.country].filter(Boolean).join(", ")}</span>
                </div>
              )}
              <div>
                <span className="detail-inline__label">{LABELS.issues} </span>
                <span>{ip.cveCount}</span>
              </div>
              <div>
                <span className="detail-inline__label">Highest {LABELS.riskScore.toLowerCase()} </span>
                <CvssScore score={ip.maxCvss} />
              </div>
            </div>
          </Card>

          <Card title="Issues on this system">
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th style={{ width: 132 }}>{LABELS.issueId}</th>
                    <th style={{ width: 56 }}>{LABELS.riskScore}</th>
                    <th style={{ width: 84 }}>Severity</th>
                    <th>{LABELS.summary}</th>
                  </tr>
                </thead>
                <tbody>
                  {ip.cveIds.map((cveId) => (
                    <IpCveRow key={cveId} cveId={cveId} onNavigate={() => navigate(`/cves/${cveId}`)} />
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

function IpCveRow({ cveId, onNavigate }: { cveId: string; onNavigate: () => void }) {
  const cve = useCve(cveId);
  if (!cve) return null;

  return (
    <tr onClick={onNavigate}>
      <td className="mono">{cve.id}</td>
      <td>
        <CvssScore score={cve.cvss} />
      </td>
      <td>
        <SeverityBadge severity={cve.severity} />
      </td>
      <td style={{ color: "var(--text-secondary)" }}>{cve.summary}</td>
    </tr>
  );
}
