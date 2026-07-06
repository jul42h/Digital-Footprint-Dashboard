import { useDashboard } from '@/context/DashboardContext';
import { useRemediation } from '@/context/RemediationContext';
import { computeNetworkRiskScore } from '@/utils/summaryGenerator';
import { useSolutions } from '@/features/solutions/hooks';

export function useDashboardSummary() {
  const { data, derived } = useDashboard();
  const solutions = useSolutions();
  const { isPendingStatus } = useRemediation();
  const critical = derived.cves.filter((c) => c.severity === 'critical').length;
  const exploited = derived.cves.filter((c) => c.exploitKnown).length;
  const assetsAtRisk = derived.ips.filter((ip) => ip.criticalCount > 0).length;
  const openFixes = solutions.filter((s) => s.status === 'open').length;
  const pendingRemediations = solutions.filter((s) => isPendingStatus(s.status)).length;
  const exposureScore = computeNetworkRiskScore(data.stats);
  const trend = derived.riskTrendView;
  const exposureDelta =
    trend.variant === "timeline" && trend.points.length >= 2
      ? trend.points[trend.points.length - 1].value - trend.points[trend.points.length - 2].value
      : 0;

  return {
    exposureScore,
    exposureDelta,
    totalVulns: data.stats.uniqueCVEs,
    critical,
    exploited,
    assetsAtRisk,
    totalAssets: data.stats.totalIPs,
    activeAlerts: derived.alerts.length,
    openFixes,
    pendingRemediations,
  };
}
