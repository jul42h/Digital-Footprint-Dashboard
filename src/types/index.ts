export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface CVE {
  id: string;
  score: number;
  severity: Severity;
  publishedDate: string;
  lastUpdated?: string;
  summary?: string;
}

export interface IPRecord {
  ip: string;
  organization: string;
  country: string;
  city?: string;
  asn?: string;
  hostnames: string[];
  operatingSystem?: string;
  ports: number[];
  transport: string[];
  services: string[];
  products: string[];
  versions: string[];
  cves: CVE[];
  riskLevel: Severity;
  tags: string[];
  vulnerabilities: string[];
  openPorts: number[];
  isp?: string;
  timestamp?: string;
  summary?: string;
  lastSeen?: string;
}

export interface DashboardStats {
  totalIPs: number;
  totalCVEs: number;
  criticalCVEs: number;
  highCVEs: number;
  mediumCVEs: number;
  lowCVEs: number;
  informationalCVEs: number;
  averageCVSS: number;
  highestCVSS: number;
  newestVulnerability: string | null;
  oldestVulnerability: string | null;
  uniqueOrganizations: number;
  uniqueCountries: number;
}

export interface CVEFlatRecord {
  cve: CVE;
  ip: string;
  organization: string;
  country: string;
  operatingSystem?: string;
  port?: number;
}

export interface DashboardData {
  ips: IPRecord[];
  stats: DashboardStats;
  cveRecords: CVEFlatRecord[];
  lastUpdated: string;
  source: 'excel' | 'fallback';
}

export type NavPage = 'dashboard' | 'ips' | 'cve' | 'analytics' | 'settings';

export interface RawExcelRow {
  [key: string]: string | number | undefined;
}
