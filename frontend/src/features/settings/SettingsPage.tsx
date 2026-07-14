import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { getApiBaseUrl } from "@/lib/api";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import { formatDate } from "@/utils/dateUtils";
import { RemediationSettings } from "./RemediationSettings";

function sourceLabel(source: string): string {
  switch (source) {
    case "api":
    case "dynamodb":
      return "AWS API · DynamoDB";
    default:
      return "No data loaded";
  }
}

export function SettingsPage() {
  const { data } = useDashboard();
  const apiBase = getApiBaseUrl() || "(same origin as FastAPI)";

  return (
    <div className="page page--narrow">
      <PageHeader
        title={NAV_LABELS.settings}
        subtitle={HELP_TEXT.settingsPage}
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
          <span className="detail-row__label">Vulnerable hosts</span>
          <span className="detail-row__value">{data.stats.vulnerableIPs}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Discovered hosts</span>
          <span className="detail-row__value">{data.stats.discoveredHosts}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Last loaded</span>
          <span className="detail-row__value">{formatDate(data.lastUpdated)}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">KEV findings</span>
          <span className="detail-row__value">{data.stats.kevFindings}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">High EPSS findings</span>
          <span className="detail-row__value">{data.stats.highEpssFindings}</span>
        </div>
        <div className="detail-row">
          <span className="detail-row__label">Records</span>
          <span className="detail-row__value">
            {data.stats.totalIPs} IPs · {data.stats.uniqueCVEs} unique CVEs · {data.stats.totalCVEs} instances
          </span>
        </div>
      </Card>

      <RemediationSettings />

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
