import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { CvssScore } from "@/components/CvssScore";
import { SeverityBadge } from "@/components/SeverityBadge";
import { LABELS } from "@/lib/copy";
import { formatLastScan } from "@/lib/format";
import { cvssToSeverity } from "@/lib/severity";
import { useIps } from "./hooks";

interface IpTableProps {
  limit?: number;
  title?: string;
}

export function IpTable({ limit, title = "IP assets" }: IpTableProps) {
  const navigate = useNavigate();
  const ips = useIps();
  const rows = limit ? ips.slice(0, limit) : ips;

  return (
    <Card
      title={title}
      action={
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {rows.length} address{rows.length !== 1 ? "es" : ""}
        </span>
      }
    >
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 120 }}>{LABELS.ipAddress}</th>
              <th style={{ width: 140 }}>{LABELS.hostname}</th>
              <th style={{ width: 72 }}>{LABELS.services}</th>
              <th style={{ width: 64 }}>{LABELS.vulns}</th>
              <th style={{ width: 88 }}>{LABELS.severity}</th>
              <th style={{ width: 120 }}>{LABELS.lastScan}</th>
              <th style={{ width: 80 }}>{LABELS.riskScore}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((ip) => (
              <tr key={ip.address} onClick={() => navigate(`/ips/${encodeURIComponent(ip.address)}`)}>
                <td className="mono">{ip.address}</td>
                <td>
                  <span className="mini-table__primary">{ip.hostname}</span>
                  {(ip.city || ip.country) && (
                    <span className="mini-table__secondary">
                      {[ip.city, ip.country].filter(Boolean).join(", ")}
                    </span>
                  )}
                </td>
                <td>{ip.serviceCount}</td>
                <td>{ip.cveCount}</td>
                <td>
                  <SeverityBadge severity={cvssToSeverity(ip.maxCvss)} />
                </td>
                <td style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  {formatLastScan(ip.lastScanAt)}
                </td>
                <td>
                  <CvssScore score={ip.maxCvss} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
