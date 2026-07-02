import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { CvssScore } from "@/components/CvssScore";
import { LABELS } from "@/lib/copy";
import { useProducts, useVendors } from "./hooks";

interface ProductRiskTableProps {
  vendorId?: string;
  title?: string;
}

export function ProductRiskTable({
  vendorId,
  title = "Software in your environment",
}: ProductRiskTableProps) {
  const navigate = useNavigate();
  const allProducts = useProducts();
  const vendors = useVendors();

  const products = vendorId
    ? allProducts.filter((p) => p.vendorId === vendorId)
    : allProducts;

  return (
    <Card title={title}>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              {!vendorId && <th style={{ width: 140 }}>{LABELS.provider}</th>}
              <th>{LABELS.software}</th>
              <th style={{ width: 100 }}>{LABELS.version}</th>
              <th style={{ width: 64 }}>{LABELS.issues}</th>
              <th style={{ width: 80 }}>{LABELS.riskScore}</th>
            </tr>
          </thead>
          <tbody>
            {products.map((p) => {
              const vendor = vendors.find((v) => v.id === p.vendorId);
              return (
                <tr key={p.id} onClick={() => navigate(`/vendors/${p.vendorId}`)}>
                  {!vendorId && <td>{vendor?.name ?? "—"}</td>}
                  <td style={{ fontWeight: 500 }}>{p.name}</td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {p.version ?? "—"}
                  </td>
                  <td>{p.cveCount}</td>
                  <td>
                    <CvssScore score={p.maxCvss} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
