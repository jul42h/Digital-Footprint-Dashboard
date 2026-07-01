import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/Card";
import { THREAT_COLOR, THREAT_LABEL, THREAT_TECH_LABEL } from "@/lib/threats";
import { useThreatDistribution } from "./hooks";

export function ThreatDistributionChart() {
  const distribution = useThreatDistribution();
  const total = distribution.reduce((sum, entry) => sum + entry.count, 0);

  const chartData = distribution.map((entry) => ({
    type: entry.type,
    label: THREAT_LABEL[entry.type],
    tech: THREAT_TECH_LABEL[entry.type],
    count: entry.count,
    color: THREAT_COLOR[entry.type],
    share: total > 0 ? Math.round((entry.count / total) * 100) : 0,
  }));

  const chartHeight = Math.max(160, chartData.length * 36 + 24);

  return (
    <Card title="Threat type distribution" className="chart-card">
      <div className="chart-card__body">
        <div style={{ height: chartHeight, width: "100%" }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 4, right: 12, left: 4, bottom: 0 }}
          >
            <XAxis
              type="number"
              allowDecimals={false}
              tick={{ fontSize: 11, fill: "var(--text-muted)" }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="label"
              width={108}
              tick={{ fontSize: 12, fill: "var(--text-secondary)" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "var(--surface-2)" }}
              contentStyle={{
                background: "var(--surface)",
                border: "0.5px solid var(--border)",
                borderRadius: 8,
                fontSize: 12,
              }}
              formatter={(value, _name, item) => [
                `${value ?? 0} open · ${item?.payload?.share ?? 0}% of total`,
                `${item?.payload?.label ?? ""} — ${item?.payload?.tech ?? ""}`,
              ]}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
              {chartData.map((entry) => (
                <Cell key={entry.type} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}
