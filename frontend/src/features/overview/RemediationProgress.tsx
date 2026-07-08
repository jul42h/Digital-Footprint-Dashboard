import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { useRemediation } from "@/context/RemediationContext";
import { useSolutions } from "@/features/solutions/hooks";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { SOLUTION_STATUS_ORDER, STATUS_COLORS } from "@/lib/remediationConfig";

export function RemediationProgress() {
  const solutions = useSolutions();
  const { getStatusLabel, isPendingStatus } = useRemediation();
  const counts = SOLUTION_STATUS_ORDER.map((status) => ({
    status,
    label: getStatusLabel(status),
    value: solutions.filter((s) => s.status === status).length,
    color: STATUS_COLORS[status],
  }));
  const pending = solutions.filter((s) => isPendingStatus(s.status)).length;

  return (
    <Card title={NAV_LABELS.fixes} className="chart-card" action={<ViewAllLink to="/solutions" />}>
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.remediationProgress}</p>
      <div className="chart-card__body">
        <div className="remediation-progress remediation-progress--compact">
          <div className="remediation-progress__chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={counts.filter((c) => c.value > 0)}
                  dataKey="value"
                  nameKey="label"
                  innerRadius="72%"
                  outerRadius="95%"
                  paddingAngle={2}
                  stroke="var(--donut-stroke)"
                  strokeWidth={2}
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
