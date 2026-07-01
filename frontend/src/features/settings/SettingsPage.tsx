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
  const apiBase = getApiBaseUrl() || "(Vite proxy → localhost:8000)";

  return (
    <div className="page" style={{ maxWidth: 720 }}>
      <PageHeader
        title={NAV_LABELS.settings}
        subtitle="Data source and AWS backend configuration."
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

      <Card title="AWS architecture">
        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.7 }}>
          <li>API Gateway → FastAPI Lambda (Mangum)</li>
          <li>FastAPI invokes <span className="mono">data-access</span> Lambda</li>
          <li>DynamoDB stores dashboard snapshot + per-IP records</li>
          <li>Athena queries curated S3 data for analytics</li>
          <li>S3 ingest trigger → ingest Lambda → refresh pipeline</li>
        </ul>
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
