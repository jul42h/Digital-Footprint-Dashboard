import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { LABELS } from "@/lib/copy";
import { useVendors } from "./hooks";

export function VendorRiskTable({
  title = "Providers ranked by risk",
  limit,
}: {
  title?: string;
  limit?: number;
}) {
  const navigate = useNavigate();
  const vendors = useVendors();
  const rows = limit ? vendors.slice(0, limit) : vendors;

  return (
    <Card title={title}>
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>{LABELS.provider}</th>
              <th style={{ width: 88 }}>{LABELS.riskLevel}</th>
              <th style={{ width: 80 }}>{LABELS.software}</th>
              <th style={{ width: 64 }}>{LABELS.issues}</th>
              <th style={{ width: 72 }}>Urgent</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((v) => (
              <tr key={v.id} onClick={() => navigate(`/vendors/${v.id}`)}>
                <td style={{ fontWeight: 500 }}>{v.name}</td>
                <td>
                  <RiskScore value={v.riskScore} />
                </td>
                <td>{v.productCount}</td>
                <td>{v.cveCount}</td>
                <td style={{ color: v.criticalCount > 0 ? "var(--sev-critical)" : undefined }}>
                  {v.criticalCount}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function RiskScore({ value }: { value: number }) {
  const color =
    value >= 80 ? "var(--sev-critical)" : value >= 60 ? "var(--sev-high)" : value >= 40 ? "var(--sev-medium)" : "var(--sev-low)";

  return (
    <span className="mono" style={{ color, fontWeight: 500 }}>
      {value}
    </span>
  );
}
