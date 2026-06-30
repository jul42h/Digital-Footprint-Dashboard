import * as XLSX from 'xlsx';
import type { DashboardData, RawExcelRow } from '@/types';
import {
  computeStats,
  flattenCVEs,
  transformRowsToIPs,
} from '@/utils/dataTransformers';
//import { DUMMY_EXCEL_ROWS } from './dummyData';

const EXCEL_PATH = '/data/shodan_data.xlsx';

// Future:
// Replace excelLoader with API Gateway + Lambda + Athena + DynamoDB
// The UI should continue consuming DashboardData from this service layer.

function workbookToRows(workbook: XLSX.WorkBook): RawExcelRow[] {
  const sheetName = workbook.SheetNames[0];
  if (!sheetName) return [];

  const sheet = workbook.Sheets[sheetName];
  return XLSX.utils.sheet_to_json<RawExcelRow>(sheet, { defval: '' });
}

function buildDashboardData(rows: RawExcelRow[], source: DashboardData['source']): DashboardData {
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

  console.warn(
    `[excelLoader] ${EXCEL_PATH} not found or empty. Using built-in fallback dataset.`,
  );
  return buildDashboardData(DUMMY_EXCEL_ROWS, 'fallback');
}

export async function reloadDashboardData(): Promise<DashboardData> {
  // Future: swap with authenticated API refresh endpoint
  return loadDashboardData();
}
