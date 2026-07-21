/* UI domain types shared across features. Produced by lib/adapters.ts from the
   raw DashboardData API shape (see types/data.ts). */

export type Severity = "critical" | "high" | "medium" | "low";

export type ThreatType =
  | "remote-code-execution"
  | "authentication"
  | "injection"
  | "denial-of-service"
  | "cross-site"
  | "information-disclosure"
  | "cryptographic"
  | "misconfiguration";

export type Transport = "TCP" | "UDP";

export interface Cve {
  id: string; // e.g. "CVE-2024-3094"
  cvss: number; // 0.0 - 10.0
  severity: Severity; // derived from cvss
  threatType: ThreatType;
  ports: number[];
  transport: Transport;
  summary: string;
  asset: string;
  vector?: string;
  publishedAt: string; // ISO 8601
  exploitKnown?: boolean; // known exploited (KEV)
  epss?: number;
  verified?: boolean;
  instanceCount?: number;
  affectedAssets?: string[];
}

export interface Kpi {
  label: string;
  value: string;
  tone?: Severity | "neutral";
  hint?: string;
  to?: string;
}

export interface ThreatCount {
  type: ThreatType;
  count: number;
}

export interface IpRecord {
  address: string;
  hostname: string;
  country?: string;
  countryCode?: string;
  city?: string;
  cveCount: number;
  criticalCount: number;
  highCount: number;
  maxCvss: number;
  cveIds: string[];
  serviceCount: number;
  lastScanAt: string; // ISO 8601
  domains?: string[];
  hostStatus?: string;
  openPortCount?: number;
  operatingSystem?: string;
  asn?: string;
  isp?: string;
  services?: string[];
  scanTypes?: string[];
}

export type SolutionStatus = "open" | "triage" | "assigned" | "resolved";

export type SolutionEffort = "low" | "medium" | "high";

export interface CveSolution {
  id: string;
  cveId: string;
  title: string;
  description: string;
  status: SolutionStatus;
  effort: SolutionEffort;
  vendorFixAvailable?: boolean;
  fixedVersion?: string;
}

export interface VendorRisk {
  id: string;
  name: string;
  riskScore: number; // 0 - 100
  productCount: number;
  cveCount: number;
  criticalCount: number;
}

export interface ProductRisk {
  id: string;
  vendorId: string;
  name: string;
  version?: string;
  cveCount: number;
  maxCvss: number;
  cveIds: string[];
}
