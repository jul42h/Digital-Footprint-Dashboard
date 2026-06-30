import type { CVE, CVEFlatRecord, DashboardStats, IPRecord, RawExcelRow } from '@/types';
import { parseDate } from '@/utils/dateUtils';
import { normalizeSeverity, scoreToSeverity, SEVERITY_ORDER } from '@/utils/severityUtils';

const COLUMN_ALIASES: Record<string, string[]> = {
  ip: ['ip address', 'ip', 'ip_address'],
  organization: ['organization', 'org', 'company'],
  country: ['country', 'country code', 'location_city'],
  city: ['city'],
  asn: ['asn'],
  hostnames: ['hostnames', 'hostname', 'host'],
  operatingSystem: ['operating system', 'os', 'operating_system'],
  ports: ['ports', 'port'],
  transport: ['transport'],
  service: ['service', 'services'],
  product: ['product', 'products'],
  version: ['version', 'versions'],
  cve: ['cve', 'cve id', 'cve_id'],
  cveScore: ['cve score', 'cvss score', 'cvss', 'score'],
  cvssSeverity: ['cvss severity', 'severity', 'risk level'],
  publishedDate: ['published date', 'published', 'published_date'],
  lastUpdated: ['last updated', 'last_updated', 'updated'],
  riskLevel: ['risk level', 'risk'],
  tags: ['tags', 'tag'],
  vulnerabilities: ['vulnerabilities', 'vulnerability'],
  openPorts: ['open ports', 'open_ports'],
  isp: ['isp'],
  timestamp: ['observed_at', 'timestamp', 'last seen', 'last_seen'],
  summary: ['summary', 'description'],
};

function normalizeKey(key: string): string {
  return key.trim().toLowerCase().replace(/[_-]+/g, ' ');
}

function getCell(row: RawExcelRow, field: keyof typeof COLUMN_ALIASES): string {
  const aliases = COLUMN_ALIASES[field];
  for (const [key, value] of Object.entries(row)) {
    const normalized = normalizeKey(key);
    if (aliases.includes(normalized) && value !== undefined && value !== null) {
      return String(value).trim();
    }
  }
  return '';
}

function splitList(value: string): string[] {
  if (!value) return [];
  return value
    .split(/[,;|]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePorts(value: string): number[] {
  return splitList(value)
    .flatMap((part) => part.split(/\s+/))
    .map((part) => parseInt(part.replace(/[^\d]/g, ''), 10))
    .filter((port) => !Number.isNaN(port));
}

function mergeUnique<T>(existing: T[], incoming: T[]): T[] {
  return [...new Set([...existing, ...incoming])];
}

function buildCVE(row: RawExcelRow): CVE | null {
  const id = getCell(row, 'cve');
  if (!id) return null;

  const scoreRaw = getCell(row, 'cveScore');
  const score = parseFloat(scoreRaw) || 0;
  const severityRaw = getCell(row, 'cvssSeverity') || getCell(row, 'riskLevel');
  const severity = severityRaw ? normalizeSeverity(severityRaw) : scoreToSeverity(score);

  return {
    id,
    score,
    severity,
    publishedDate: getCell(row, 'publishedDate'),
    lastUpdated: getCell(row, 'lastUpdated') || undefined,
    summary: getCell(row, 'summary') || undefined,
  };
}

function computeRiskLevel(cves: CVE[]): IPRecord['riskLevel'] {
  if (cves.length === 0) return 'Informational';
  return cves.reduce((max, cve) =>
    SEVERITY_ORDER[cve.severity] > SEVERITY_ORDER[max] ? cve.severity : max,
  cves[0].severity);
}

function mergeIPRecord(existing: IPRecord, row: RawExcelRow): IPRecord {
  const cve = buildCVE(row);
  const ports = parsePorts(getCell(row, 'ports') || getCell(row, 'openPorts'));
  const openPorts = parsePorts(getCell(row, 'openPorts'));

  const mergedCVEs = cve
    ? [...existing.cves.filter((item) => item.id !== cve.id), cve]
    : existing.cves;

  return {
    ...existing,
    organization: getCell(row, 'organization') || existing.organization,
    country: getCell(row, 'country') || existing.country,
    city: getCell(row, 'city') || existing.city,
    asn: getCell(row, 'asn') || existing.asn,
    hostnames: mergeUnique(existing.hostnames, splitList(getCell(row, 'hostnames'))),
    operatingSystem: getCell(row, 'operatingSystem') || existing.operatingSystem,
    ports: mergeUnique(existing.ports, ports),
    transport: mergeUnique(existing.transport, splitList(getCell(row, 'transport'))),
    services: mergeUnique(existing.services, splitList(getCell(row, 'service'))),
    products: mergeUnique(existing.products, splitList(getCell(row, 'product'))),
    versions: mergeUnique(existing.versions, splitList(getCell(row, 'version'))),
    cves: mergedCVEs,
    riskLevel: computeRiskLevel(mergedCVEs),
    tags: mergeUnique(existing.tags, splitList(getCell(row, 'tags'))),
    vulnerabilities: mergeUnique(existing.vulnerabilities, splitList(getCell(row, 'vulnerabilities'))),
    openPorts: mergeUnique(existing.openPorts, openPorts.length ? openPorts : ports),
    isp: getCell(row, 'isp') || existing.isp,
    timestamp: getCell(row, 'timestamp') || existing.timestamp,
    summary: getCell(row, 'summary') || existing.summary,
    lastSeen: getCell(row, 'timestamp') || existing.lastSeen,
  };
}

export function transformRowsToIPs(rows: RawExcelRow[]): IPRecord[] {
  const ipMap = new Map<string, IPRecord>();

  for (const row of rows) {
    const ip = getCell(row, 'ip');
    if (!ip) continue;

    const existing = ipMap.get(ip);
    if (existing) {
      ipMap.set(ip, mergeIPRecord(existing, row));
    } else {
      ipMap.set(ip, mergeIPRecord(
        {
          ip,
          organization: getCell(row, 'organization'),
          country: getCell(row, 'country'),
          city: getCell(row, 'city') || undefined,
          asn: getCell(row, 'asn') || undefined,
          hostnames: splitList(getCell(row, 'hostnames')),
          operatingSystem: getCell(row, 'operatingSystem') || undefined,
          ports: [],
          transport: [],
          services: [],
          products: [],
          versions: [],
          cves: [],
          riskLevel: 'Informational',
          tags: [],
          vulnerabilities: [],
          openPorts: [],
          isp: getCell(row, 'isp') || undefined,
          timestamp: getCell(row, 'timestamp') || undefined,
          summary: getCell(row, 'summary') || undefined,
          lastSeen: getCell(row, 'timestamp') || undefined,
        },
        row,
      ));
    }
  }

  return Array.from(ipMap.values()).sort((a, b) => b.cves.length - a.cves.length);
}

export function flattenCVEs(ips: IPRecord[]): CVEFlatRecord[] {
  const records: CVEFlatRecord[] = [];

  for (const ip of ips) {
    for (const cve of ip.cves) {
      records.push({
        cve,
        ip: ip.ip,
        organization: ip.organization,
        country: ip.country,
        operatingSystem: ip.operatingSystem,
        port: ip.ports[0],
      });
    }
  }

  return records.sort(
    (a, b) => (parseDate(b.cve.publishedDate)?.getTime() ?? 0) - (parseDate(a.cve.publishedDate)?.getTime() ?? 0),
  );
}

export function computeStats(ips: IPRecord[]): DashboardStats {
  const allCVEs = ips.flatMap((ip) => ip.cves);
  const scores = allCVEs.map((cve) => cve.score).filter((score) => score > 0);
  const publishedDates = allCVEs
    .map((cve) => parseDate(cve.publishedDate))
    .filter((date): date is Date => date !== null)
    .sort((a, b) => a.getTime() - b.getTime());

  const countBySeverity = (severity: string) =>
    allCVEs.filter((cve) => cve.severity === severity).length;

  return {
    totalIPs: ips.length,
    totalCVEs: allCVEs.length,
    criticalCVEs: countBySeverity('Critical'),
    highCVEs: countBySeverity('High'),
    mediumCVEs: countBySeverity('Medium'),
    lowCVEs: countBySeverity('Low'),
    informationalCVEs: countBySeverity('Informational'),
    averageCVSS: scores.length
      ? Math.round((scores.reduce((sum, score) => sum + score, 0) / scores.length) * 10) / 10
      : 0,
    highestCVSS: scores.length ? Math.max(...scores) : 0,
    newestVulnerability: publishedDates.length
      ? publishedDates[publishedDates.length - 1].toISOString()
      : null,
    oldestVulnerability: publishedDates.length ? publishedDates[0].toISOString() : null,
    uniqueOrganizations: new Set(ips.map((ip) => ip.organization).filter(Boolean)).size,
    uniqueCountries: new Set(ips.map((ip) => ip.country).filter(Boolean)).size,
  };
}

export function getRiskScore(ip: IPRecord): number {
  if (ip.cves.length === 0) return 0;
  return Math.round(ip.cves.reduce((sum, cve) => sum + cve.score, 0) * 10) / 10;
}

export function getTopRiskIPs(ips: IPRecord[], limit = 10): Array<IPRecord & { riskScore: number }> {
  return ips
    .map((ip) => ({ ...ip, riskScore: getRiskScore(ip) }))
    .filter((ip) => ip.cves.length > 0)
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, limit);
}
