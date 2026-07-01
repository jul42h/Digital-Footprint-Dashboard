import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import { Card } from "@/components/Card";
import {
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  severityColorValue,
} from "@/lib/severity";
import { useSeverityCounts } from "./hooks";

export function SeverityDonut() {
  const counts = useSeverityCounts();
  const total = counts.reduce((s, c) => s + c.count, 0);

  const chartData = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    label: SEVERITY_LABEL[sev],
    value: counts.find((c) => c.severity === sev)?.count ?? 0,
    color: severityColorValue(sev),
  }));

  return (
    <Card title="Severity breakdown" className="chart-card">
      <div className="chart-card__body">
        <div className="severity-donut">
        <div className="severity-donut__visual">
          <div className="severity-donut__chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="label"
                  innerRadius="68%"
                  outerRadius="88%"
                  paddingAngle={2}
                  stroke="none"
                >
                  {chartData.map((d) => (
                    <Cell key={d.severity} fill={d.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="donut-center">
              <span className="donut-center__value">{total}</span>
              <span className="donut-center__label">total</span>
            </div>
          </div>
        </div>

        <ul className="donut-legend severity-donut__legend">
          {chartData.map((d) => (
            <li key={d.severity} className="donut-legend__item">
              <span className="donut-legend__swatch" style={{ background: d.color }} />
              <span className="donut-legend__label">{d.label}</span>
              <span className="donut-legend__count">{d.value}</span>
            </li>
          ))}
        </ul>
        </div>
      </div>
    </Card>
  );
}
