import type { DashboardData, Severity } from '@/types';
import { toMonthKey } from '@/utils/dateUtils';

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

export function buildChartData(data: DashboardData) {
  const { stats, ips, cveRecords } = data;

  const severityData = SEVERITIES.map((name) => ({
    name,
    value:
      name === 'Critical' ? stats.criticalCVEs :
      name === 'High' ? stats.highCVEs :
      name === 'Medium' ? stats.mediumCVEs :
      name === 'Low' ? stats.lowCVEs :
      stats.informationalCVEs,
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

  const orgCounts = new Map<string, number>();
  for (const record of cveRecords) {
    if (record.organization) {
      orgCounts.set(record.organization, (orgCounts.get(record.organization) ?? 0) + 1);
    }
  }
  const topOrgs = Array.from(orgCounts.entries())
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8)
    .map(([organization, count]) => ({ organization, count }));

  const countryCounts = new Map<string, number>();
  for (const ip of ips.filter((item) => item.cves.length > 0)) {
    if (ip.country) countryCounts.set(ip.country, (countryCounts.get(ip.country) ?? 0) + 1);
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

  const orgSeverity = new Map<string, Record<Severity, number>>();
  for (const record of cveRecords) {
    if (!record.organization) continue;
    const current = orgSeverity.get(record.organization) ?? {
      Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0,
    };
    current[record.cve.severity] += 1;
    orgSeverity.set(record.organization, current);
  }
  const severityByOrg = Array.from(orgSeverity.entries())
    .map(([organization, counts]) => ({ organization, ...counts }))
    .sort((a, b) =>
      (b.Critical + b.High + b.Medium) - (a.Critical + a.High + a.Medium),
    )
    .slice(0, 6);

  return {
    severityData,
    topIPs,
    cvesOverTime,
    topOrgs,
    countries,
    portHeatmap,
    osDistribution,
    severityByOrg,
    severities: SEVERITIES.filter((s) => s !== 'Informational') as Severity[],
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
  const versions = countMap(ips.flatMap((ip) => ip.versions));

  const orgHosts = new Map<string, number>();
  for (const ip of ips.filter((item) => item.cves.length > 0)) {
    orgHosts.set(ip.organization, (orgHosts.get(ip.organization) ?? 0) + 1);
  }
  const vulnerableOrgs = Array.from(orgHosts.entries())
    .sort(([, a], [, b]) => b - a)
    .map(([name, count]) => ({ name, count }));

  const countryDistribution = countMap(ips.map((ip) => ip.country));

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
    versions,
    vulnerableOrgs,
    countryDistribution,
    avgCVSSByOrg,
  };
}
