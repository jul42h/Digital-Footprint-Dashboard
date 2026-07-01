import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { formatDate } from "@/utils/dateUtils";

export function SettingsPage() {
  const { data } = useDashboard();

  return (
    <div className="page" style={{ maxWidth: 720 }}>
      <PageHeader
        title={NAV_LABELS.settings}
        subtitle="Data source and configuration for the Digital Footprint dashboard."
      />

      <Card title="Data source">
        <div className="detail-row">
          <span className="detail-row__label">Source</span>
          <span className="detail-row__value">
            {data.source === "excel" ? "Shodan Excel export" : "No data file found"}
          </span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">File path</span>
          <span className="detail-row__value mono">public/data/shodan_data.xlsx</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Last loaded</span>
          <span className="detail-row__value">{formatDate(data.lastUpdated)}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Records</span>
          <span className="detail-row__value">
            {data.stats.totalIPs} IPs · {data.stats.totalCVEs} CVEs
          </span>
        </div>
      </Card>

      <Card title="Future integration">
        <p style={{ margin: 0, fontSize: 14, lineHeight: 1.55, color: "var(--text-secondary)" }}>
          This prototype loads data the same way as Digital-Footprint-Dashboard-main: from a Shodan
          Excel export via the browser. Future versions can swap the loader for API Gateway, Lambda,
          Athena, and DynamoDB without changing the UI components.
        </p>
        <ul style={{ margin: "12px 0 0", paddingLeft: 20, fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.6 }}>
          <li>API Gateway endpoint configuration</li>
          <li>Data refresh intervals</li>
          <li>Alert thresholds and notifications</li>
          <li>Export and reporting preferences</li>
        </ul>
      </Card>
    </div>
  );
}
