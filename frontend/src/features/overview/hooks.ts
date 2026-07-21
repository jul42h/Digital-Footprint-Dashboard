import { useMemo } from 'react';
import type { ThreatCount } from '@/types';
import { THREAT_ORDER } from '@/lib/threats';
import { useDashboard } from '@/context/DashboardContext';

export function useThreatDistribution(): ThreatCount[] {
  const cves = useDashboard().derived.cves;
  return useMemo(() => {
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
  }, [cves]);
}
