import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { KpiCard } from "@/components/KpiCard";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { buildAnalyticsData, buildChartData, buildDomainFootprint } from "@/utils/chartData";
import { formatMonthKey } from "@/utils/dateUtils";
import { computeNetworkRiskScore } from "@/utils/summaryGenerator";
import { severityColorValue } from "@/lib/severity";
import { GeoExposureMap } from "@/features/overview/GeoExposureMap";

export function AnalyticsPage() {
  const { data } = useDashboard();
  const charts = buildChartData(data);
  const analytics = buildAnalyticsData(data);
  const domains = buildDomainFootprint(data);
  const riskScore = computeNetworkRiskScore(data.stats);

  const cvesOverTime = charts.cvesOverTime.map((entry) => ({
    name: formatMonthKey(entry.month),
    count: entry.count,
  }));

  return (
    <div className="page dashboard">
      <PageHeader
        title={NAV_LABELS.analytics}
        subtitle={HELP_TEXT.analyticsPage}
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Exposure score", value: String(riskScore), tone: riskScore >= 70 ? "critical" : "neutral" }} />
        <KpiCard kpi={{ label: "Unique CVEs", value: String(data.stats.uniqueCVEs), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Known exploited", value: String(data.stats.kevFindings), tone: data.stats.kevFindings > 0 ? "critical" : "neutral" }} />
        <KpiCard kpi={{ label: "High EPSS", value: String(data.stats.highEpssFindings), tone: data.stats.highEpssFindings > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "At-risk hosts", value: String(data.stats.vulnerableIPs), tone: data.stats.vulnerableIPs > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "Discovered hosts", value: String(data.stats.discoveredHosts), tone: "neutral" }} />
      </div>

      <div className="dashboard-2col dashboard-2col--geo">
        <GeoExposureMap />
        <AnalyticsBarCard title="CVE findings over time" data={cvesOverTime} />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsBarCard title="Top IPs by finding count" data={charts.topIPs.map((d) => ({ name: d.ip, count: d.count }))} />
        <AnalyticsBarCard title="Vulnerable ports" data={charts.portHeatmap.map((d) => ({ name: d.port, count: d.count }))} />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsPieCard title="OS distribution" data={charts.osDistribution} />
        <AnalyticsBarCard title="Domain footprint" data={domains} horizontal />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsBarCard title="Services" data={analytics.services.slice(0, 8)} horizontal />
        <AnalyticsBarCard title="Products with CVE linkage" data={analytics.products.slice(0, 8)} horizontal />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsBarCard title="Country distribution" data={analytics.countryDistribution.slice(0, 8)} horizontal />
        <AnalyticsBarCard title="Avg CVSS by organization" data={analytics.avgCVSSByOrg.slice(0, 8).map((d) => ({ name: d.name, count: d.count }))} horizontal />
      </div>
    </div>
  );
}

function AnalyticsBarCard({
  title,
  data,
  horizontal = false,
}: {
  title: string;
  data: Array<{ name: string; count: number }>;
  horizontal?: boolean;
}) {
  const accent = severityColorValue("high");
  const height = horizontal ? Math.max(160, data.length * 36 + 24) : 220;

  if (data.length === 0) {
    return (
      <Card title={title} className="chart-card">
        <p className="geo-map__empty">No data for this chart.</p>
      </Card>
    );
  }

  return (
    <Card title={title} className="chart-card">
      <div className="chart-card__body">
        <div style={{ height, width: "100%" }}>
          <ResponsiveContainer width="100%" height="100%">
            {horizontal ? (
              <BarChart data={data} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 11, fill: "var(--text-secondary)" }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "var(--surface)", border: "0.5px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="count" fill={accent} radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            ) : (
              <BarChart data={data} margin={{ top: 8, right: 8, left: -8, bottom: 40 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--text-muted)" }} angle={-30} textAnchor="end" height={50} />
                <YAxis tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "var(--surface)", border: "0.5px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="count" fill={accent} radius={[4, 4, 0, 0]} />
              </BarChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}

function AnalyticsPieCard({ title, data }: { title: string; data: Array<{ name: string; value: number }> }) {
  const colors = ["#e0463f", "#e2742a", "#d9a21b", "#3b8fd6", "#5a9e6f", "#8a92a0"];
  const filtered = data.filter((d) => d.value > 0);

  if (filtered.length === 0) {
    return (
      <Card title={title} className="chart-card">
        <p className="geo-map__empty">No data for this chart.</p>
      </Card>
    );
  }

  return (
    <Card title={title} className="chart-card">
      <div className="chart-card__body">
        <div style={{ height: 220, width: "100%" }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={filtered} dataKey="value" nameKey="name" innerRadius="50%" outerRadius="80%" paddingAngle={2} stroke="none">
                {filtered.map((entry, i) => (
                  <Cell key={entry.name} fill={colors[i % colors.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: "var(--surface)", border: "0.5px solid var(--border)", borderRadius: 8, fontSize: 12 }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}
