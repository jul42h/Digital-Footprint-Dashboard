import type { DashboardData, SourceSeverity } from '@/types/data';
import { countryLabel, normalizeCountryCode } from '@/lib/geo';
import { toMonthKey } from '@/utils/dateUtils';

const SEVERITIES: SourceSeverity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

export function buildChartData(data: DashboardData) {
  const { stats, ips, cveRecords } = data;

  const severityData = SEVERITIES.map((name) => ({
    name,
    value:
      name === 'Critical'
        ? stats.criticalCVEs
        : name === 'High'
          ? stats.highCVEs
          : name === 'Medium'
            ? stats.mediumCVEs
            : name === 'Low'
              ? stats.lowCVEs
              : stats.informationalCVEs,
  }));

  const topIPs = ips
    .map((ip) => ({ ip: ip.ip, count: ip.cves.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const monthCounts = new Map<string, number>();
  for (const record of cveRecords) {
    const key = toMonthKey(record.cve.publishedDate);
    if (key) monthCounts.set(key, (monthCounts.get(key) ?? 0) + 1);
  }
  const cvesOverTime = Array.from(monthCounts.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([month, count]) => ({ month, count }));

  const countryCounts = new Map<string, number>();
  for (const ip of ips.filter((item) => item.cves.length > 0)) {
    const code = normalizeCountryCode(ip.country);
    if (!code) continue;
    const label = countryLabel(code);
    countryCounts.set(label, (countryCounts.get(label) ?? 0) + 1);
  }
  const countries = Array.from(countryCounts.entries())
    .sort(([, a], [, b]) => b - a)
    .map(([country, count]) => ({ country, count }));

  const portCounts = new Map<string, number>();
  for (const ip of ips) {
    for (const port of ip.ports) {
      portCounts.set(String(port), (portCounts.get(String(port)) ?? 0) + ip.cves.length);
    }
  }
  const portHeatmap = Array.from(portCounts.entries())
    .sort(([, a], [, b]) => b - a)
    .slice(0, 15)
    .map(([port, count]) => ({ port, count }));

  const osCounts = new Map<string, number>();
  for (const ip of ips) {
    if (ip.operatingSystem) {
      osCounts.set(ip.operatingSystem, (osCounts.get(ip.operatingSystem) ?? 0) + 1);
    }
  }
  const osDistribution = Array.from(osCounts.entries())
    .sort(([, a], [, b]) => b - a)
    .map(([name, value]) => ({ name, value }));

  return {
    severityData,
    topIPs,
    cvesOverTime,
    countries,
    portHeatmap,
    osDistribution,
  };
}

export function buildAnalyticsData(data: DashboardData) {
  const { ips, cveRecords } = data;

  const countMap = (values: string[]) => {
    const map = new Map<string, number>();
    for (const value of values) {
      if (value) map.set(value, (map.get(value) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .sort(([, a], [, b]) => b - a)
      .map(([name, count]) => ({ name, count }));
  };

  const services = countMap(ips.flatMap((ip) => ip.services));
  const operatingSystems = countMap(ips.map((ip) => ip.operatingSystem ?? ''));
  const ports = countMap(ips.flatMap((ip) => ip.ports.map(String)));
  const products = countMap(ips.flatMap((ip) => ip.products));
  const countryDistribution = countMap(
    ips
      .map((ip) => {
        const code = normalizeCountryCode(ip.country);
        return code ? countryLabel(code) : '';
      })
      .filter(Boolean),
  );

  const orgScores = new Map<string, { total: number; count: number }>();
  for (const record of cveRecords) {
    if (!record.organization || !record.cve.score) continue;
    const current = orgScores.get(record.organization) ?? { total: 0, count: 0 };
    current.total += record.cve.score;
    current.count += 1;
    orgScores.set(record.organization, current);
  }
  const avgCVSSByOrg = Array.from(orgScores.entries())
    .map(([name, { total, count }]) => ({
      name,
      count: Math.round((total / count) * 10) / 10,
    }))
    .sort((a, b) => b.count - a.count);

  return {
    services,
    operatingSystems,
    ports,
    products,
    countryDistribution,
    avgCVSSByOrg,
  };
}
