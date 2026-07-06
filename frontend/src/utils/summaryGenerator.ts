import type { DashboardStats } from '@/types/data';

export function computeNetworkRiskScore(stats: DashboardStats): number {
  if (stats.totalCVEs === 0) return 0;

  const weighted =
    stats.criticalCVEs * 10 +
    stats.highCVEs * 7 +
    stats.mediumCVEs * 4 +
    stats.lowCVEs * 2 +
    stats.informationalCVEs * 0.5;

  const raw = (weighted / Math.max(stats.totalCVEs, 1)) * (stats.averageCVSS / 10) * 10;
  return Math.min(100, Math.round(raw * 10) / 10);
}
