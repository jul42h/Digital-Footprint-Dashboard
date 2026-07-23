export type SourceSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface SourceCVE {
  id: string;
  score: number;
  severity: SourceSeverity;
  cvssVersion?: string;
  publishedDate: string;
  lastUpdated?: string;
  summary?: string;
  kev?: boolean;
  epss?: number;
  rankingEpss?: number;
  port?: number;
  product?: string;
  service?: string;
  verified?: boolean;
}

export interface SourceIPRecord {
  ip: string;
  /** Masked display text for the viewer role (e.g. "10.20.30.xxx"). Absent
   *  for admin/analyst, where `ip` itself is safe to render directly. */
  ipDisplay?: string;
  organization: string;
  country: string;
  city?: string;
  asn?: string;
  /** Scan source range in CIDR notation, e.g. "129.8.242.0/24". */
  ipRange?: string;
  hostnames: string[];
  domains?: string[];
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
  hostStatus?: string;
  hostStatusReason?: string;
  scanTypes?: string[];
}

export interface DashboardStats {
  totalIPs: number;
  /** Total CVE findings across all hosts (instances). */
  totalCVEs: number;
  /** Distinct CVE IDs in the dataset. */
  uniqueCVEs: number;
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
  vulnerableIPs: number;
  discoveredHosts: number;
  discoveryOnlyHosts: number;
  kevFindings: number;
  highEpssFindings: number;
  verifiedFindings: number;
}

export interface CVEFlatRecord {
  cve: SourceCVE;
  ip: string;
  /** Masked display text for the viewer role, mirrors SourceIPRecord.ipDisplay
   *  for the same host. Absent for admin/analyst. */
  ipDisplay?: string;
  organization: string;
  country: string;
  operatingSystem?: string;
  port?: number;
  product?: string;
  service?: string;
  verified?: boolean;
  scanType?: string;
}

export interface DashboardData {
  ips: SourceIPRecord[];
  stats: DashboardStats;
  cveRecords: CVEFlatRecord[];
  scanSourceCounts?: Record<string, number>;
  lastUpdated: string;
  source: 'empty' | 'api' | 'dynamodb';
}
