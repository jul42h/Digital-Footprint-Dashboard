import type { SeverityCount, ThreatCount } from '@/types';
import { THREAT_ORDER } from '@/lib/threats';
import { SEVERITY_ORDER } from '@/lib/severity';
import { useDashboard } from '@/context/DashboardContext';

export function useSeverityCounts(): SeverityCount[] {
  const cves = useDashboard().derived.cves;
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: cves.filter((c) => c.severity === severity).length,
  }));
}

export function useRiskTrend() {
  return useDashboard().derived.riskTrend;
}

export function useThreatDistribution(): ThreatCount[] {
  const cves = useDashboard().derived.cves;
  const counts = new Map<string, number>();
  for (const cve of cves) {
    counts.set(cve.threatType, (counts.get(cve.threatType) ?? 0) + 1);
  }

  return THREAT_ORDER.map((type) => ({
    type,
    count: counts.get(type) ?? 0,
  }))
    .filter((entry) => entry.count > 0)
    .sort((a, b) => b.count - a.count);
}
