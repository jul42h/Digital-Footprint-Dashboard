import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ViewAllLink } from "@/components/ViewAllLink";
import { cvssToSeverity } from "@/lib/severity";
import { useIps } from "@/features/ips/hooks";

export function AtRiskAssets({ limit = 4 }: { limit?: number }) {
  const navigate = useNavigate();
  const assets = useIps()
    .slice()
    .sort((a, b) => b.maxCvss - a.maxCvss)
    .slice(0, limit);

  return (
    <Card title="Highest-risk assets" action={<ViewAllLink to="/ips" />}>
      <table className="mini-table">
        <thead>
          <tr>
            <th>Asset</th>
            <th>Vulns</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr
              key={asset.address}
              onClick={() => navigate(`/ips/${encodeURIComponent(asset.address)}`)}
            >
              <td>
                <span className="mini-table__primary">{asset.hostname}</span>
                <span className="mini-table__secondary mono">{asset.address}</span>
                {(asset.city || asset.country) && (
                  <span className="mini-table__secondary">
                    {[asset.city, asset.country].filter(Boolean).join(", ")}
                  </span>
                )}
              </td>
              <td>{asset.cveCount}</td>
              <td>
                <SeverityBadge severity={cvssToSeverity(asset.maxCvss)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
