import { useDashboard } from '@/context/DashboardContext';
import { computeNetworkRiskScore } from '@/utils/summaryGenerator';

export function useDashboardSummary() {
  const { data, derived } = useDashboard();
  const critical = derived.cves.filter((c) => c.severity === 'critical').length;
  const exploited = derived.cves.filter((c) => c.exploitKnown).length;
  const assetsAtRisk = derived.ips.filter((ip) => ip.criticalCount > 0).length;
  const openFixes = derived.solutions.filter((s) => s.status === 'open').length;
  const pendingRemediations = derived.solutions.filter(
    (s) => s.status === 'open' || s.status === 'triage',
  ).length;
  const exposureScore = computeNetworkRiskScore(data.stats);
  const trend = derived.riskTrend;
  const exposureDelta =
    trend.length >= 2 ? trend[trend.length - 1].score - trend[trend.length - 2].score : 0;

  return {
    exposureScore,
    exposureDelta,
    totalVulns: data.stats.totalCVEs,
    critical,
    exploited,
    assetsAtRisk,
    totalAssets: data.stats.totalIPs,
    activeAlerts: derived.alerts.length,
    openFixes,
    pendingRemediations,
  };
}
