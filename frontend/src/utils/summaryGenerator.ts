import type { DashboardStats, SourceIPRecord } from '@/types/data';

function topEntry(counts: Map<string, number>): string {
  let best = '';
  let bestCount = 0;
  for (const [key, count] of counts) {
    if (count > bestCount) {
      best = key;
      bestCount = count;
    }
  }
  return best || 'Unknown';
}

export function generateExecutiveSummary(stats: DashboardStats, ips: SourceIPRecord[]): string {
  const osCounts = new Map<string, number>();
  const serviceCounts = new Map<string, number>();

  for (const ip of ips) {
    if (ip.operatingSystem) {
      osCounts.set(ip.operatingSystem, (osCounts.get(ip.operatingSystem) ?? 0) + 1);
    }
    for (const service of ip.services) {
      serviceCounts.set(service, (serviceCounts.get(service) ?? 0) + 1);
    }
  }

  const vulnerableHosts = ips.filter((ip) => ip.cves.length > 0).length;
  const topOS = topEntry(osCounts);
  const topService = topEntry(serviceCounts);

  if (stats.totalCVEs === 0) {
    return 'No vulnerability data loaded. Place shodan_data.xlsx in public/data/ or refresh when data is available.';
  }

  return [
    `${vulnerableHosts} vulnerable host${vulnerableHosts === 1 ? '' : 's'} across ${stats.uniqueOrganizations} organization${stats.uniqueOrganizations === 1 ? '' : 's'}.`,
    `Average CVSS score is ${stats.averageCVSS || 0}.`,
    `${stats.criticalCVEs} critical vulnerabilit${stats.criticalCVEs === 1 ? 'y requires' : 'ies require'} immediate attention.`,
    `Most common OS: ${topOS}. Most common service: ${topService}.`,
  ].join(' ');
}

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
