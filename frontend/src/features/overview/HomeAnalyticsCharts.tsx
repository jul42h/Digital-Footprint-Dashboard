import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card } from "@/components/Card";
import { useDashboard } from "@/context/DashboardContext";
import { buildAnalyticsData, buildChartData } from "@/utils/chartData";
import { severityColorValue } from "@/lib/severity";

export function HomeTopIpsChart() {
  const { data } = useDashboard();
  const charts = buildChartData(data);
  const accent = severityColorValue("high");
  const top = charts.topIPs.slice(0, 6);

  return (
    <Card title="Highest-exposure IPs" className="chart-card">
      <div className="chart-card__body">
        <div style={{ height: 200, width: "100%" }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={top} margin={{ top: 8, right: 12, left: 4, bottom: 48 }}>
              <XAxis
                dataKey="ip"
                tick={{ fontSize: 10, fill: "var(--text-muted)" }}
                angle={-30}
                textAnchor="end"
                height={52}
                interval={0}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                axisLine={false}
                tickLine={false}
                width={28}
              />
              <Tooltip
                contentStyle={{
                  background: "var(--surface)",
                  border: "0.5px solid var(--border)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill={accent} radius={[4, 4, 0, 0]} name="CVEs" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}

export function HomeExposureBreakdown() {
  const { data } = useDashboard();
  const analytics = buildAnalyticsData(data);
  const accent = severityColorValue("medium");

  const rows = [
    { name: "Open ports", count: analytics.ports.slice(0, 1).reduce((s, p) => s + p.count, 0) || analytics.ports.length },
    { name: "Services", count: analytics.services.length },
    { name: "Products", count: analytics.products.length },
    { name: "Countries", count: data.stats.uniqueCountries },
    { name: "Organizations", count: data.stats.uniqueOrganizations },
  ].filter((r) => r.count > 0);

  return (
    <Card title="Footprint summary" className="chart-card">
      <div className="chart-card__body">
        <div style={{ height: 200, width: "100%" }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={rows}
              layout="vertical"
              margin={{ top: 4, right: 12, left: 4, bottom: 0 }}
            >
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={96} tick={{ fontSize: 11, fill: "var(--text-secondary)" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  background: "var(--surface)",
                  border: "0.5px solid var(--border)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill={accent} radius={[0, 4, 4, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <p className="card-footnote">Breadth of your external attack surface.</p>
    </Card>
  );
}
