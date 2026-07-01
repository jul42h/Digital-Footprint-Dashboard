import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { useSolutions } from "@/features/solutions/hooks";
import { NAV_LABELS } from "@/lib/copy";

const STATUS_COLORS: Record<string, string> = {
  open: "var(--sev-critical)",
  triage: "var(--sev-medium)",
  assigned: "var(--accent)",
  resolved: "var(--status-resolved)",
};

const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  triage: "Review",
  assigned: "Active",
  resolved: "Done",
};

export function RemediationProgress() {
  const solutions = useSolutions();
  const counts = ["open", "triage", "assigned", "resolved"].map((status) => ({
    status,
    label: STATUS_LABELS[status],
    value: solutions.filter((s) => s.status === status).length,
    color: STATUS_COLORS[status],
  }));
  const pending = solutions.filter((s) => s.status === "open" || s.status === "triage").length;

  return (
    <Card title={NAV_LABELS.fixes} className="chart-card" action={<ViewAllLink to="/solutions" />}>
      <div className="chart-card__body">
        <div className="remediation-progress remediation-progress--compact">
          <div className="remediation-progress__chart">
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie
                  data={counts.filter((c) => c.value > 0)}
                  dataKey="value"
                  nameKey="label"
                  innerRadius="52%"
                  outerRadius="80%"
                  paddingAngle={2}
                  stroke="none"
                >
                  {counts
                    .filter((c) => c.value > 0)
                    .map((entry) => (
                      <Cell key={entry.status} fill={entry.color} />
                    ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--surface)",
                    border: "0.5px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="donut-center">
              <span className="donut-center__value">{pending}</span>
              <span className="donut-center__label">pending</span>
            </div>
          </div>

          <ul className="donut-legend donut-legend--compact">
            {counts.map((entry) => (
              <li key={entry.status} className="donut-legend__item">
                <span className="donut-legend__swatch" style={{ background: entry.color }} />
                <span className="donut-legend__label">{entry.label}</span>
                <span className="donut-legend__count">{entry.value}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  );
}
