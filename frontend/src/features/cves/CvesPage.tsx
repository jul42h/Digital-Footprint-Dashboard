import { KpiCard } from "@/components/KpiCard";
import { PageHeader } from "@/components/PageHeader";
import { useDashboard } from "@/context/DashboardContext";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { CveTable } from "./CveTable";

export function CvesPage() {
  const { data, derived } = useDashboard();
  const critical = derived.cves.filter((c) => c.severity === "critical").length;
  const high = derived.cves.filter((c) => c.severity === "high").length;

  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.issues}
        subtitle={HELP_TEXT.cvesPage}
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Unique CVEs", value: String(data.stats.uniqueCVEs), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Exposure instances", value: String(data.stats.totalCVEs), tone: "neutral" }} />
        <KpiCard
          kpi={{
            label: "Critical (unique)",
            value: String(critical),
            tone: critical > 0 ? "critical" : "neutral",
          }}
        />
        <KpiCard
          kpi={{
            label: "High (unique)",
            value: String(high),
            tone: high > 0 ? "high" : "neutral",
          }}
        />
        <KpiCard
          kpi={{
            label: "Known exploited",
            value: String(data.stats.kevFindings),
            tone: data.stats.kevFindings > 0 ? "high" : "neutral",
          }}
        />
        <KpiCard
          kpi={{
            label: "High EPSS",
            value: String(data.stats.highEpssFindings),
            tone: data.stats.highEpssFindings > 0 ? "medium" : "neutral",
          }}
        />
      </div>

      <CveTable title="All issues" />
    </div>
  );
}
