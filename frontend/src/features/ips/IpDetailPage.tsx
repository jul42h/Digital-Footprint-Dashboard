import { Link, useNavigate, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { LABELS, NAV_LABELS } from "@/lib/copy";
import { formatIpLocation } from "@/lib/geo";
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
              {formatIpLocation(ip.city, ip.country) && (
                <div>
                  <span className="detail-inline__label">{LABELS.location} </span>
                  <span>{formatIpLocation(ip.city, ip.country)}</span>
                </div>
              )}
              {ip.domains && ip.domains.length > 0 && (
                <div>
                  <span className="detail-inline__label">Domains </span>
                  <span>{ip.domains.join(", ")}</span>
                </div>
              )}
              {ip.hostStatus && (
                <div>
                  <span className="detail-inline__label">Host status </span>
                  <span>{ip.hostStatus}</span>
                </div>
              )}
              {ip.operatingSystem && (
                <div>
                  <span className="detail-inline__label">Operating system </span>
                  <span>{ip.operatingSystem}</span>
                </div>
              )}
              {ip.asn && (
                <div>
                  <span className="detail-inline__label">ASN </span>
                  <span className="mono">{ip.asn}</span>
                </div>
              )}
              {ip.isp && (
                <div>
                  <span className="detail-inline__label">ISP </span>
                  <span>{ip.isp}</span>
                </div>
              )}
              {ip.services && ip.services.length > 0 && (
                <div>
                  <span className="detail-inline__label">{LABELS.services} </span>
                  <span>{ip.services.join(", ")}</span>
                </div>
              )}
              {ip.scanTypes && ip.scanTypes.length > 0 && (
                <div>
                  <span className="detail-inline__label">Scan sources </span>
                  <span>{ip.scanTypes.join(", ")}</span>
                </div>
              )}
              {ip.openPortCount != null && ip.openPortCount > 0 && (
                <div>
                  <span className="detail-inline__label">Open ports </span>
                  <span>{ip.openPortCount}</span>
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
