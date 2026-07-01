/* Domain types shared across features. These mirror the shape your
   pipeline API is expected to return for vulnerability data — adjust
   to match your real schema. */

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
  ports: number[]; // affected ports
  transport: Transport; // TCP / UDP
  summary: string; // vulnerability summary
  asset: string; // affected asset / service
  vector?: string; // CVSS vector string
  publishedAt: string; // ISO 8601
  exploitKnown?: boolean; // known exploited (KEV)
}

export interface Kpi {
  label: string;
  value: string;
  tone?: Severity | "neutral";
  hint?: string;
  to?: string;
}

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface ThreatCount {
  type: ThreatType;
  count: number;
}

export interface RiskPoint {
  date: string; // e.g. "Jun 14"
  score: number; // 0 - 100 aggregate risk score
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
}

export interface SecurityAlert {
  id: string;
  message: string;
  severity: Severity;
  source: string;
  occurredAt: string; // ISO 8601
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
