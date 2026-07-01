import * as XLSX from 'xlsx';
import type { DashboardData, RawExcelRow } from '@/types/data';
import { computeStats, flattenCVEs, transformRowsToIPs } from '@/utils/dataTransformers';

const EXCEL_PATH = '/data/shodan_data.xlsx';

function workbookToRows(workbook: XLSX.WorkBook): RawExcelRow[] {
  const sheetName = workbook.SheetNames[0];
  if (!sheetName) return [];

  const sheet = workbook.Sheets[sheetName];
  return XLSX.utils.sheet_to_json<RawExcelRow>(sheet, { defval: '' });
}

function buildDashboardData(
  rows: RawExcelRow[],
  source: DashboardData['source'],
): DashboardData {
  const ips = transformRowsToIPs(rows);
  const stats = computeStats(ips);
  const cveRecords = flattenCVEs(ips);

  return {
    ips,
    stats,
    cveRecords,
    lastUpdated: new Date().toISOString(),
    source,
  };
}

async function fetchExcelBuffer(): Promise<ArrayBuffer | null> {
  try {
    const response = await fetch(EXCEL_PATH);
    if (!response.ok) return null;
    return response.arrayBuffer();
  } catch {
    return null;
  }
}

export async function loadDashboardData(): Promise<DashboardData> {
  const buffer = await fetchExcelBuffer();

  if (buffer) {
    const workbook = XLSX.read(buffer, { type: 'array' });
    const rows = workbookToRows(workbook);
    if (rows.length > 0) {
      return buildDashboardData(rows, 'excel');
    }
  }

  console.warn(`[excelLoader] ${EXCEL_PATH} not found or empty. Returning empty dataset.`);
  return buildDashboardData([], 'empty');
}

export async function reloadDashboardData(): Promise<DashboardData> {
  return loadDashboardData();
}
