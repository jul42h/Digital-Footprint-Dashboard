import { useDashboard } from "@/context/DashboardContext";
import { HELP_TEXT } from "@/lib/copy";

export function DataStatusBanner() {
  const { data } = useDashboard();

  if (data.source === "empty") {
    return (
      <div className="data-banner data-banner--error" role="status">
        {HELP_TEXT.dataUnavailable}
      </div>
    );
  }

  if (data.stats.totalCVEs === 0 && data.stats.discoveredHosts === 0) {
    return (
      <div className="data-banner data-banner--warn" role="status">
        {HELP_TEXT.dataEmpty}
      </div>
    );
  }

  if (data.stats.totalCVEs === 0 && data.stats.discoveredHosts > 0) {
    return (
      <div className="data-banner data-banner--info" role="status">
        {data.stats.discoveredHosts} hosts were discovered but no CVE findings are loaded yet.
        DNS discovery records may not include vulnerabilities.
      </div>
    );
  }

  return null;
}
