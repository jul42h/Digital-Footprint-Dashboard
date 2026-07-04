import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card } from "@/components/Card";
import { useDashboard } from "@/context/DashboardContext";
import { HELP_TEXT } from "@/lib/copy";
import { buildChartData } from "@/utils/chartData";
import { severityColorValue } from "@/lib/severity";

export function HomeTopIpsChart() {
  const { data } = useDashboard();
  const charts = buildChartData(data);
  const accent = severityColorValue("high");
  const top = charts.topIPs.slice(0, 6);

  return (
    <Card title="Highest exposure IPs" className="chart-card">
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.topIps}</p>
      <div className="chart-card__body">
        <div className="chart-area chart-area--compact">
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
