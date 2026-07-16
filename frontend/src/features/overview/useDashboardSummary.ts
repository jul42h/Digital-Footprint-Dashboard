import { useMemo } from 'react';
import { useDashboard } from '@/context/DashboardContext';
import { useRemediation } from '@/context/RemediationContext';
import { computeNetworkRiskScore } from '@/utils/summaryGenerator';
import { useSolutions } from '@/features/solutions/hooks';

export function useDashboardSummary() {
  const { data, derived } = useDashboard();
  const solutions = useSolutions();
  const { isPendingStatus } = useRemediation();

  return useMemo(() => {
    const critical = derived.cves.filter((c) => c.severity === 'critical').length;
    const exploited = derived.cves.filter((c) => c.exploitKnown).length;
    const assetsAtRisk = derived.ips.filter((ip) => ip.criticalCount > 0).length;
    const pendingRemediations = solutions.filter((s) => isPendingStatus(s.status)).length;
    const maxEpss = derived.cves.reduce<number | null>(
      (max, c) => (c.epss != null && (max == null || c.epss > max) ? c.epss : max),
      null,
    );
    const exposureScore = computeNetworkRiskScore(data.stats, maxEpss);

    return {
      exposureScore,
      critical,
      exploited,
      assetsAtRisk,
      pendingRemediations,
    };
  }, [data.stats, derived, isPendingStatus, solutions]);
}
