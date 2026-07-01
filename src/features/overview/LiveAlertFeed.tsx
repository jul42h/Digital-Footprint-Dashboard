import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useLiveAlerts } from "./useLiveAlerts";

function formatTimeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function LiveAlertFeed({ limit = 6 }: { limit?: number }) {
  const alerts = useLiveAlerts(limit);

  return (
    <Card
      title={
        <span className="live-feed__title">
          <span className="live-dot" aria-hidden />
          Active alerts
        </span>
      }
      action={
        <span className="live-feed__status">
          {alerts.length} active
        </span>
      }
    >
      <ul className="alert-feed">
        {alerts.map((alert) => (
          <li key={alert.id} className="alert-feed__item">
            <div className="alert-feed__main">
              <SeverityBadge severity={alert.severity} />
              <span className="alert-feed__message">{alert.message}</span>
            </div>
            <div className="alert-feed__meta">
              <span className="alert-feed__source">{alert.source}</span>
              <span className="alert-feed__time">{formatTimeAgo(alert.occurredAt)}</span>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
