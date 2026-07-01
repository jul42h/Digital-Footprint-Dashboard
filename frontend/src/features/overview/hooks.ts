import type { Kpi, SeverityCount, ThreatCount } from '@/types';
import { THREAT_ORDER } from '@/lib/threats';
import { SEVERITY_ORDER } from '@/lib/severity';
import { useDashboard } from '@/context/DashboardContext';

export function useKpis(): Kpi[] {
  const { data, derived } = useDashboard();
  const critical = derived.cves.filter((c) => c.severity === 'critical').length;
  const avg =
    derived.cves.length > 0
      ? derived.cves.reduce((s, c) => s + c.cvss, 0) / derived.cves.length
      : 0;

  return [
    { label: 'Total CVEs', value: String(data.stats.totalCVEs), tone: 'neutral' },
    { label: 'Critical', value: String(critical), tone: 'critical' },
    { label: 'Average CVSS', value: avg.toFixed(1), tone: 'neutral' },
    { label: 'Affected assets', value: String(derived.ips.filter((ip) => ip.cveCount > 0).length), tone: 'neutral' },
  ];
}

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

export function useExposureScore(): number {
  const { data } = useDashboard();
  if (data.stats.totalCVEs === 0) return 0;
  const { stats } = data;
  const weighted =
    stats.criticalCVEs * 10 +
    stats.highCVEs * 7 +
    stats.mediumCVEs * 4 +
    stats.lowCVEs * 2;
  return Math.min(100, Math.round((weighted / Math.max(stats.totalCVEs, 1)) * 10));
}
