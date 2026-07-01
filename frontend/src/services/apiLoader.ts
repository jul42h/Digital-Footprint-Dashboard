import type { DashboardData } from "@/types/data";
import { apiUrl } from "@/lib/api";

export async function loadDashboardFromApi(): Promise<DashboardData> {
  const response = await fetch(apiUrl("/api/v1/dashboard"));
  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${response.statusText}`);
  }
  const data = (await response.json()) as DashboardData;
  return { ...data, source: data.source === "excel" ? "excel" : "api" };
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
