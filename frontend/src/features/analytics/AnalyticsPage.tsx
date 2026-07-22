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
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { buildAnalyticsData, buildChartData, buildDomainFootprint } from "@/utils/chartData";
import { formatMonthKey } from "@/utils/dateUtils";
import { computeNetworkRiskScore } from "@/utils/summaryGenerator";
import { chartCategoryColor } from "@/lib/severity";
import { useTheme } from "@/context/ThemeContext";
import { GeoExposureMap } from "./GeoExposureMap";

export function AnalyticsPage() {
  /* Chart colors below are resolved from CSS custom properties at render
     time (SVG fill attributes can't take var() the way inline styles can),
     so this page must re-render on theme change or the charts keep painting
     the previous theme's colors. */
  useTheme();
  const { data } = useDashboard();
  const charts = buildChartData(data);
  const analytics = buildAnalyticsData(data);
  const domains = buildDomainFootprint(data);
  const maxEpss = data.cveRecords.reduce<number | null>((max, record) => {
    const epss = record.cve.epss ?? record.cve.rankingEpss;
    return epss != null && (max == null || epss > max) ? epss : max;
  }, null);
  const riskScore = computeNetworkRiskScore(data.stats, maxEpss);

  const cvesOverTime = charts.cvesOverTime.map((entry) => ({
    name: formatMonthKey(entry.month),
    count: entry.count,
  }));

  return (
    <div className="page dashboard">
      <PageHeader
        title={NAV_LABELS.analytics}
        subtitle={HELP_TEXT.analyticsPage}
      />

      <div className="kpi-strip">
        <KpiCard
          kpi={{
            label: "Risk score",
            value: String(riskScore),
            tone: riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : "neutral",
          }}
        />
        <KpiCard kpi={{ label: "Unique CVEs", value: String(data.stats.uniqueCVEs), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Known exploited", value: String(data.stats.kevFindings), tone: data.stats.kevFindings > 0 ? "critical" : "neutral" }} />
        <KpiCard kpi={{ label: "High EPSS", value: String(data.stats.highEpssFindings), tone: data.stats.highEpssFindings > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "At-risk hosts", value: String(data.stats.vulnerableIPs), tone: data.stats.vulnerableIPs > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "Discovered hosts", value: String(data.stats.discoveredHosts), tone: "neutral" }} />
      </div>

      <AnalyticsSection title="Exposure overview" description="Where vulnerable assets are located and how findings have changed over time.">
        <div className="dashboard-2col dashboard-2col--geo">
          <GeoExposureMap />
          <AnalyticsBarCard title="CVE findings over time" data={cvesOverTime} />
        </div>
      </AnalyticsSection>

      <AnalyticsSection title="Risk concentration" description="Hosts and network entry points carrying the greatest finding volume.">
        <div className="dashboard-charts-row">
          <AnalyticsBarCard title="Top IPs by finding count" data={charts.topIPs.map((d) => ({ name: d.ip, count: d.count }))} />
          <AnalyticsBarCard title="Vulnerable ports" data={charts.portHeatmap.map((d) => ({ name: d.port, count: d.count }))} />
        </div>
      </AnalyticsSection>

      <AnalyticsSection title="Technology footprint" description="Operating systems, domains, services, and products represented in the scan.">
        <div className="dashboard-charts-row">
          <AnalyticsPieCard title="OS distribution" data={charts.osDistribution} />
          <AnalyticsBarCard title="Domain footprint" data={domains} horizontal />
        </div>
        <div className="dashboard-charts-row">
          <AnalyticsBarCard title="Services" data={analytics.services.slice(0, 8)} horizontal />
          <AnalyticsBarCard title="Products with CVE linkage" data={analytics.products.slice(0, 8)} horizontal />
        </div>
      </AnalyticsSection>

      <AnalyticsSection title="Organization context" description="Geographic distribution and average severity by observed organization.">
        <div className="dashboard-charts-row">
          <AnalyticsBarCard title="Country distribution" data={analytics.countryDistribution.slice(0, 8)} horizontal />
          <AnalyticsBarCard title="Avg CVSS by organization" data={analytics.avgCVSSByOrg.slice(0, 8).map((d) => ({ name: d.name, count: d.count }))} horizontal />
        </div>
      </AnalyticsSection>
    </div>
  );
}

function AnalyticsSection({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  const id = `analytics-${title.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <section className="analytics-section" aria-labelledby={id}>
      <header className="analytics-section__header">
        <h2 id={id} className="analytics-section__title">{title}</h2>
        <p className="analytics-section__description">{description}</p>
      </header>
      {children}
    </section>
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
  const accent = chartCategoryColor(0);
  const height = horizontal ? Math.max(160, data.length * 36 + 24) : 220;

  if (data.length === 0) {
    return (
      <Card title={title} className="chart-card">
        <p className="empty-note">No data for this chart.</p>
      </Card>
    );
  }

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
  const filtered = data.filter((d) => d.value > 0);
  const total = filtered.reduce((sum, d) => sum + d.value, 0);

  if (filtered.length === 0) {
    return (
      <Card title={title} className="chart-card">
        <p className="empty-note">No data for this chart.</p>
      </Card>
    );
  }

  const chartData = filtered.map((entry, i) => ({ ...entry, color: chartCategoryColor(i) }));

  return (
    <Card title={title} className="chart-card">
      <div className="chart-card__body">
        <div className="chart-donut">
          <div className="chart-donut__visual">
            <div className="chart-donut__chart">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={chartData} dataKey="value" nameKey="name" innerRadius="68%" outerRadius="88%" paddingAngle={2} stroke="none">
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "var(--surface)", border: "0.5px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center">
                <span className="donut-center__value">{total}</span>
                <span className="donut-center__label">total</span>
              </div>
            </div>
          </div>

          <ul className="donut-legend chart-donut__legend">
            {chartData.map((entry) => (
              <li key={entry.name} className="donut-legend__item">
                <span className="donut-legend__swatch" style={{ background: entry.color }} />
                <span className="donut-legend__label">{entry.name}</span>
                <span className="donut-legend__count">{entry.value}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  );
}
