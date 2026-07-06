import type { DashboardData } from "@/types/data";
import { checkApiHealth, loadDashboardFromApi, refreshDashboardViaApi } from "@/services/apiLoader";
import { emptyDashboard } from "@/services/emptyDashboard";

async function loadFromApi(): Promise<DashboardData> {
  const healthy = await checkApiHealth();
  if (!healthy) {
    throw new Error("API is unavailable. Start the footprint-api server and refresh.");
  }
  return loadDashboardFromApi();
}

export async function loadDashboardData(): Promise<DashboardData> {
  try {
    return await loadFromApi();
  } catch (err) {
    console.warn("[dashboardLoader] API unavailable:", err);
    return emptyDashboard();
  }
}

export async function reloadDashboardData(): Promise<DashboardData> {
  try {
    const healthy = await checkApiHealth();
    if (!healthy) {
      throw new Error("API is unavailable");
    }
    await refreshDashboardViaApi();
    return loadDashboardFromApi();
  } catch (err) {
    console.warn("[dashboardLoader] Refresh failed:", err);
    return emptyDashboard();
  }
}
