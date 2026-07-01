import { KpiCard } from "@/components/KpiCard";
import { useKpis } from "./hooks";

export function KpiStrip() {
  const kpis = useKpis();
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
        gap: 12,
      }}
    >
      {kpis.map((kpi) => (
        <KpiCard key={kpi.label} kpi={kpi} />
      ))}
    </div>
  );
}
