import type { DashboardData } from "@/types/data";
import { emptyDashboardStats } from "@/services/emptyDashboard";
import { authFetch } from "@/lib/api";

function normalizeDashboard(data: DashboardData): DashboardData {
  const defaults = emptyDashboardStats();
  const stats = { ...defaults, ...data.stats };
  return {
    ...data,
    stats: {
      ...stats,
      uniqueCVEs: stats.uniqueCVEs || stats.totalCVEs,
    },
    scanSourceCounts: data.scanSourceCounts ?? {},
    source: data.source,
  };
}

export async function loadDashboardFromApi(): Promise<DashboardData> {
  const response = await authFetch("/api/v1/dashboard");
  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${response.statusText}`);
  }
  const data = (await response.json()) as DashboardData;
  return normalizeDashboard(data);
}

export async function refreshDashboardViaApi(): Promise<void> {
  const response = await authFetch("/api/v1/dashboard/refresh", { method: "POST" });
  if (response.status === 403) {
    // Triggering a re-scan is admin-only. Non-admin roles hitting Refresh
    // should just re-fetch the existing payload (below, via
    // loadDashboardFromApi) rather than have this treated as a failure —
    // reloadDashboardData's catch-all previously wiped the dashboard to its
    // empty state on *any* thrown error, which would otherwise nuke a
    // perfectly good view just because this one step wasn't permitted.
    return;
  }
  if (!response.ok) {
    throw new Error(`Refresh failed: ${response.status}`);
  }
}

export async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await authFetch("/api/v1/health");
    return response.ok;
  } catch {
    return false;
  }
}
