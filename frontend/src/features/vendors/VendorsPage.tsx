import { KpiCard } from "@/components/KpiCard";
import { PageHeader } from "@/components/PageHeader";
import { NAV_LABELS } from "@/lib/copy";
import { VendorRiskTable } from "./VendorRiskTable";
import { ProductRiskTable } from "./ProductRiskTable";
import { useProducts, useVendors } from "./hooks";

export function VendorsPage() {
  const vendors = useVendors();
  const products = useProducts();
  const highConcern = vendors.filter((v) => v.riskScore >= 70).length;
  const totalUrgent = vendors.reduce((sum, v) => sum + v.criticalCount, 0);

  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.providers}
        subtitle="Which software makers and products are contributing the most risk to your environment."
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Providers tracked", value: String(vendors.length), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Software products", value: String(products.length), tone: "neutral" }} />
        <KpiCard kpi={{ label: "High concern", value: String(highConcern), tone: highConcern > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "Urgent issues", value: String(totalUrgent), tone: totalUrgent > 0 ? "critical" : "neutral" }} />
      </div>

      <div className="home-charts">
        <VendorRiskTable />
        <ProductRiskTable />
      </div>
    </div>
  );
}
