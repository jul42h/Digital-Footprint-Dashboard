import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/Card";
import { severityColorValue } from "@/lib/severity";
import { useRiskTrendView } from "./hooks";

const TIMELINE_VARIANTS = new Set(["timeline", "hourly"]);

export function RiskTrendChart() {
  const view = useRiskTrendView();
  const stroke = severityColorValue("high");
  const barFill = severityColorValue(
    view.variant === "exploitability" ? "critical" : "medium",
  );

  if (view.points.length === 0) {
    return (
      <Card title={view.title} className="chart-card chart-card--compact">
        {view.subtitle && (
          <p className="card-footnote card-footnote--tight">{view.subtitle}</p>
        )}
        <p className="geo-map__empty">Not enough dated findings to plot a trend yet.</p>
      </Card>
    );
  }

  const chartData = view.points.map((point) => ({
    label: point.label,
    value: point.value,
  }));

  const isTimeline = TIMELINE_VARIANTS.has(view.variant);
  const snapshotHeight = Math.min(Math.max(view.points.length * 34 + 20, 108), 176);

  return (
    <Card title={view.title} className="chart-card chart-card--compact">
      {view.subtitle && (
        <p className="card-footnote card-footnote--tight">{view.subtitle}</p>
      )}
      <div className="chart-card__body">
        <div
          className={
            isTimeline
              ? "chart-area chart-area--trend chart-area--home"
              : "chart-area chart-area--snapshot chart-area--home"
          }
          style={isTimeline ? undefined : { height: snapshotHeight }}
        >
          <ResponsiveContainer width="100%" height="100%">
            {isTimeline ? (
              <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={stroke} stopOpacity={0.22} />
                    <stop offset="100%" stopColor={stroke} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                  axisLine={false}
                  tickLine={false}
                  interval={view.variant === "hourly" ? 0 : 2}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                  axisLine={false}
                  tickLine={false}
                  width={36}
                />
                <Tooltip
                  cursor={{ stroke: "var(--border-strong)" }}
                  contentStyle={{
                    background: "var(--surface)",
                    border: "0.5px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "var(--text-secondary)" }}
                  labelFormatter={(label) => `Time: ${label}`}
                  formatter={(value) => [`${value ?? 0} findings`, "Observed"]}
                />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke={stroke}
                  strokeWidth={2}
                  fill="url(#riskFill)"
                />
              </AreaChart>
            ) : (
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
                  width={120}
                  tick={{ fontSize: 11, fill: "var(--text-secondary)" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "0.5px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  formatter={(value) => [`${value ?? 0}`, "Findings"]}
                />
                <Bar dataKey="value" fill={barFill} radius={[0, 4, 4, 0]} barSize={18} />
              </BarChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}
