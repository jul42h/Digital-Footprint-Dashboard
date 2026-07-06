import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card } from "@/components/Card";
import { useDashboard } from "@/context/DashboardContext";
import { HELP_TEXT } from "@/lib/copy";
import { buildScanSourceData } from "@/utils/chartData";
import { severityColorValue } from "@/lib/severity";

export function ScanSourceInsight() {
  const { data } = useDashboard();
  const sources = buildScanSourceData(data);
  const accent = severityColorValue("medium");

  if (sources.length === 0) {
    return (
      <Card title="Scan sources" className="chart-card">
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.scanSources}</p>
        <p className="geo-map__empty">No scan source metadata in the current dataset.</p>
      </Card>
    );
  }

  return (
    <Card title="Scan sources" className="chart-card">
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.scanSources}</p>
      <div className="chart-card__body">
        <div className="chart-area chart-area--compact">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={sources} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 0 }}>
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
              <YAxis
                type="category"
                dataKey="name"
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
              />
              <Bar dataKey="count" fill={accent} radius={[0, 4, 4, 0]} barSize={18} name="Records" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}
