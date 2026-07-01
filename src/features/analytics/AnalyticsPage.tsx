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
import { NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { buildAnalyticsData, buildChartData } from "@/utils/chartData";
import { computeNetworkRiskScore } from "@/utils/summaryGenerator";
import { severityColorValue } from "@/lib/severity";
import { GeoExposureMap } from "@/features/overview/GeoExposureMap";

export function AnalyticsPage() {
  const { data } = useDashboard();
  const charts = buildChartData(data);
  const analytics = buildAnalyticsData(data);
  const riskScore = computeNetworkRiskScore(data.stats);

  return (
    <div className="page dashboard">
      <PageHeader
        title={NAV_LABELS.analytics}
        subtitle="Deeper breakdown of services, geography, ports, and operating systems from Shodan data."
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Network risk score", value: String(riskScore), tone: riskScore >= 70 ? "critical" : "neutral" }} />
        <KpiCard kpi={{ label: "Organizations", value: String(data.stats.uniqueOrganizations), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Countries", value: String(data.stats.uniqueCountries), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Highest CVSS", value: String(data.stats.highestCVSS), tone: "high" }} />
      </div>

      <div className="home-geo-row">
        <GeoExposureMap />
        <AnalyticsBarCard title="Country distribution" data={analytics.countryDistribution.slice(0, 8)} horizontal />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsBarCard title="Top IPs by CVE count" data={charts.topIPs.map((d) => ({ name: d.ip, count: d.count }))} />
        <AnalyticsBarCard title="Open ports (weighted)" data={charts.portHeatmap.map((d) => ({ name: d.port, count: d.count }))} />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsPieCard title="OS distribution" data={charts.osDistribution} />
        <AnalyticsBarCard title="Services" data={analytics.services.slice(0, 8)} horizontal />
      </div>

      <div className="dashboard-charts-row">
        <AnalyticsBarCard title="Products" data={analytics.products.slice(0, 8)} horizontal />
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
