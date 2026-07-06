import type { DashboardData } from "@/types/data";
import { emptyDashboardStats } from "@/services/emptyDashboard";
import { apiUrl } from "@/lib/api";

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
    source: data.source === "dynamodb" ? "dynamodb" : data.source === "api" ? "api" : data.source,
  };
}

export async function loadDashboardFromApi(): Promise<DashboardData> {
  const response = await fetch(apiUrl("/api/v1/dashboard"));
  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${response.statusText}`);
  }
  const data = (await response.json()) as DashboardData;
  return normalizeDashboard(data);
}

export async function refreshDashboardViaApi(): Promise<void> {
  const response = await fetch(apiUrl("/api/v1/dashboard/refresh"), { method: "POST" });
  if (!response.ok) {
    throw new Error(`Refresh failed: ${response.status}`);
  }
}

export async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await fetch(apiUrl("/api/v1/health"));
    return response.ok;
  } catch {
    return false;
  }
}
