import type { DashboardData, DashboardStats } from '@/types/data';

export function emptyDashboardStats(): DashboardStats {
  return {
    totalIPs: 0,
    totalCVEs: 0,
    uniqueCVEs: 0,
    criticalCVEs: 0,
    highCVEs: 0,
    mediumCVEs: 0,
    lowCVEs: 0,
    informationalCVEs: 0,
    averageCVSS: 0,
    highestCVSS: 0,
    newestVulnerability: null,
    oldestVulnerability: null,
    uniqueOrganizations: 0,
    uniqueCountries: 0,
    vulnerableIPs: 0,
    discoveredHosts: 0,
    discoveryOnlyHosts: 0,
    kevFindings: 0,
    highEpssFindings: 0,
    verifiedFindings: 0,
  };
}

export function emptyDashboard(): DashboardData {
  return {
    ips: [],
    stats: emptyDashboardStats(),
    cveRecords: [],
    scanSourceCounts: {},
    lastUpdated: new Date().toISOString(),
    source: 'empty',
  };
}
