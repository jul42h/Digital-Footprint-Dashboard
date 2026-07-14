import { Link, useNavigate, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { CvssScore } from "@/components/CvssScore";
import { LABELS, NAV_LABELS } from "@/lib/copy";
import { useCve } from "@/features/cves/hooks";
import { useProductsForVendor, useVendor } from "./hooks";

export function VendorDetailPage() {
  const { id = "" } = useParams();
  const vendor = useVendor(id);
  const products = useProductsForVendor(id);
  const navigate = useNavigate();

  return (
    <div className="page page--narrow">
      <Link to="/vendors" className="back-link">
        ← {NAV_LABELS.providers}
      </Link>

      {!vendor ? (
        <Card>We could not find that provider.</Card>
      ) : (
        <>
          <Card title={vendor.name}>
            <div className="detail-inline">
              <div>
                <span className="detail-inline__label">{LABELS.riskLevel} </span>
                <span className="mono" style={{ fontWeight: 500 }}>{vendor.riskScore}</span>
              </div>
              <div>
                <span className="detail-inline__label">{LABELS.software} </span>
                <span>{vendor.productCount}</span>
              </div>
              <div>
                <span className="detail-inline__label">{LABELS.issues} </span>
                <span>{vendor.cveCount}</span>
              </div>
              <div>
                <span className="detail-inline__label">Urgent </span>
                <span style={{ color: vendor.criticalCount > 0 ? "var(--sev-critical)" : undefined }}>
                  {vendor.criticalCount}
                </span>
              </div>
            </div>
          </Card>

          {products.map((product) => (
            <Card key={product.id} title={`${product.name}${product.version ? ` · ${product.version}` : ""}`}>
              <p className="card-footnote" style={{ marginTop: 0, marginBottom: 12 }}>
                {product.cveCount} linked issue{product.cveCount !== 1 ? "s" : ""} · highest {LABELS.riskScore.toLowerCase()}{" "}
                <CvssScore score={product.maxCvss} />
              </p>
              <div className="table-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th style={{ width: 132 }}>{LABELS.issueId}</th>
                      <th>{LABELS.summary}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {product.cveIds.map((cveId) => (
                      <ProductCveRow
                        key={cveId}
                        cveId={cveId}
                        onNavigate={() => navigate(`/cves/${cveId}`)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          ))}
        </>
      )}
    </div>
  );
}

function ProductCveRow({ cveId, onNavigate }: { cveId: string; onNavigate: () => void }) {
  const cve = useCve(cveId);
  if (!cve) return null;

  return (
    <tr onClick={onNavigate}>
      <td className="mono">{cve.id}</td>
      <td style={{ color: "var(--text-secondary)" }}>{cve.summary}</td>
    </tr>
  );
}
