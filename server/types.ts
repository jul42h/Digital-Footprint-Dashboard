export interface CVEItem {
  id: string;
  description: string;
  cvssScore: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  published: string;
  affectedProducts: string[];
  affectedCount: number;
  exploitability: string | null;
  vector: string | null;
}

export interface IPIntel {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  threatTags: string[];
  lastSeen: string;
  ports: number[];
}

export interface DashboardStats {
  totalCVEs: number;
  criticalCVEs: number;
  highCVEs: number;
  monitoredIPs: number;
  highRiskIPs: number;
  totalAffectedProducts: number;
  avgCvssScore: number;
}

export interface ThreatEvent {
  id: string;
  timestamp: string;
  type: 'cve' | 'ip' | 'scan' | 'exploit';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
}
