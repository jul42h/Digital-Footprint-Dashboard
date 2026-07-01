import { KpiCard } from "@/components/KpiCard";
import { useHomeKpis } from "./homeHooks";

export function HomeKpiStrip() {
  const kpis = useHomeKpis();
  return (
    <div className="kpi-strip">
      {kpis.map((kpi) => (
        <KpiCard key={kpi.label} kpi={kpi} />
      ))}
    </div>
  );
}
