import type { DashboardData } from "@/types/data";
import { checkApiHealth, loadDashboardFromApi, refreshDashboardViaApi } from "@/services/apiLoader";
import { loadDashboardData as loadExcelData, reloadDashboardData as reloadExcelData } from "@/services/excelLoader";

const USE_API = import.meta.env.VITE_USE_API !== "false";

async function loadFromApiOrExcel(): Promise<DashboardData> {
  if (!USE_API) {
    return loadExcelData();
  }

  try {
    const healthy = await checkApiHealth();
    if (healthy) {
      return loadDashboardFromApi();
    }
  } catch {
    // fall through to Excel
  }

  console.warn("[dashboardLoader] API unavailable, falling back to Excel");
  return loadExcelData();
}

export async function loadDashboardData(): Promise<DashboardData> {
  return loadFromApiOrExcel();
}

export async function reloadDashboardData(): Promise<DashboardData> {
  if (!USE_API) {
    return reloadExcelData();
  }

  try {
    const healthy = await checkApiHealth();
    if (healthy) {
      await refreshDashboardViaApi();
      return loadDashboardFromApi();
    }
  } catch {
    // fall through
  }

  return reloadExcelData();
}
