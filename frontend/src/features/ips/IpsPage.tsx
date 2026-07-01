import { KpiCard } from "@/components/KpiCard";
import { PageHeader } from "@/components/PageHeader";
import { NAV_LABELS } from "@/lib/copy";
import { IpTable } from "./IpTable";
import { useIps } from "./hooks";

export function IpsPage() {
  const ips = useIps();
  const totalIssues = ips.reduce((sum, ip) => sum + ip.cveCount, 0);
  const withCritical = ips.filter((ip) => ip.criticalCount > 0).length;

  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.systems}
        subtitle="Scanned network addresses with discovered services, vulnerabilities, and severity per asset."
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Addresses scanned", value: String(ips.length), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Total issues", value: String(totalIssues), tone: "neutral" }} />
        <KpiCard
          kpi={{
            label: "Critical severity",
            value: String(withCritical),
            tone: withCritical > 0 ? "critical" : "neutral",
          }}
        />
      </div>

      <IpTable title="All scanned assets" />
    </div>
  );
}
