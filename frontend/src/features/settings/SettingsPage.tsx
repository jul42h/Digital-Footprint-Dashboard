import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { getApiBaseUrl } from "@/lib/api";
import { NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { formatDate } from "@/utils/dateUtils";

function sourceLabel(source: string): string {
  switch (source) {
    case "api":
      return "FastAPI backend";
    case "dynamodb":
      return "AWS API · DynamoDB";
    case "excel":
      return "Local Excel fallback";
    default:
      return "No data";
  }
}

export function SettingsPage() {
  const { data } = useDashboard();
  const apiBase = getApiBaseUrl() || "(same origin as FastAPI)";

  return (
    <div className="page" style={{ maxWidth: 720 }}>
      <PageHeader
        title={NAV_LABELS.settings}
        subtitle="Data source and API configuration."
      />

      <Card title="Data source">
        <div className="detail-row">
          <span className="detail-row__label">Source</span>
          <span className="detail-row__value">{sourceLabel(data.source)}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">API endpoint</span>
          <span className="detail-row__value mono">{apiBase}/api/v1/dashboard</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Excel fallback</span>
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

      <Card title="Keyboard shortcuts">
        <div className="detail-row">
          <span className="detail-row__label">Refresh data</span>
          <span className="detail-row__value">
            <kbd className="shortcuts-list__key">R</kbd>
          </span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Toggle sidebar</span>
          <span className="detail-row__value">
            <kbd className="shortcuts-list__key">[</kbd>
          </span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Show shortcuts</span>
          <span className="detail-row__value">
            <kbd className="shortcuts-list__key">?</kbd>
          </span>
        </div>
      </Card>
    </div>
  );
}
