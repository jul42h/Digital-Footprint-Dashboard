import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/Card";
import { severityColorValue } from "@/lib/severity";
import { HELP_TEXT } from "@/lib/copy";
import { useRiskTrend } from "./hooks";

export function RiskTrendChart() {
  const points = useRiskTrend();
  const stroke = severityColorValue("high");

  return (
    <Card title="Exposure trend">
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.exposureTrend}</p>
      <div className="chart-area chart-area--trend">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <defs>
              <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={stroke} stopOpacity={0.22} />
                <stop offset="100%" stopColor={stroke} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="date"
              tick={{ fontSize: 11, fill: "var(--text-muted)" }}
              axisLine={false}
              tickLine={false}
              interval={2}
            />
            <YAxis
              domain={[0, 100]}
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
              labelFormatter={(date) => `Date: ${date}`}
              formatter={(value) => [`${value ?? 0} / 100`, "Exposure score"]}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke={stroke}
              strokeWidth={2}
              fill="url(#riskFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
