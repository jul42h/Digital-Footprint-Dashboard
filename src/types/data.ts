export type SourceSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface SourceCVE {
  id: string;
  score: number;
  severity: SourceSeverity;
  publishedDate: string;
  lastUpdated?: string;
  summary?: string;
  kev?: boolean;
}

export interface SourceIPRecord {
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
  cves: SourceCVE[];
  riskLevel: SourceSeverity;
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
  cve: SourceCVE;
  ip: string;
  organization: string;
  country: string;
  operatingSystem?: string;
  port?: number;
}

export interface DashboardData {
  ips: SourceIPRecord[];
  stats: DashboardStats;
  cveRecords: CVEFlatRecord[];
  lastUpdated: string;
  source: 'excel' | 'empty';
}

export interface RawExcelRow {
  [key: string]: string | number | undefined;
}
