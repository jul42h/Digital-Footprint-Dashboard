import type {
  Cve,
  CveSolution,
  IpRecord,
  ProductRisk,
  RiskTrendView,
  VendorRisk,
} from '@/types';
import type { CVEFlatRecord, DashboardData } from '@/types/data';
import { compareSolutionPriority, exploitabilityScore } from '@/lib/exploitability';
import { inferThreatType } from '@/lib/inferThreat';
import { countryLabel, normalizeCountryCode } from '@/lib/geo';
import { cvssToSeverity, sourceSeverityToUi } from '@/lib/severity';
import {
  formatDayKey,
  formatHourLabel,
  formatShortDay,
  parseDate,
  toDayKey,
} from '@/utils/dateUtils';
import {
  buildChartData,
  buildExploitabilitySignals,
  buildScanSourceData,
} from '@/utils/chartData';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d+/i;

function isRealCveId(id: string): boolean {
  return CVE_ID_PATTERN.test(id);
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function transportForRecord(record: CVEFlatRecord, data: DashboardData): 'TCP' | 'UDP' {
  const ip = data.ips.find((item) => item.ip === record.ip);
  const transport = ip?.transport[0]?.toUpperCase();
  return transport === 'UDP' ? 'UDP' : 'TCP';
}

function mergeCve(existing: Cve, incoming: Cve): Cve {
  return {
    ...incoming,
    ports: [...new Set([...existing.ports, ...incoming.ports])],
    affectedAssets: [...new Set([...(existing.affectedAssets ?? [existing.asset]), ...(incoming.affectedAssets ?? [incoming.asset])])],
    instanceCount: (existing.instanceCount ?? 1) + 1,
    exploitKnown: existing.exploitKnown || incoming.exploitKnown,
    verified: existing.verified || incoming.verified,
    epss: Math.max(existing.epss ?? 0, incoming.epss ?? 0) || undefined,
    cvss: Math.max(existing.cvss, incoming.cvss),
    severity:
      exploitabilityScore(incoming) > exploitabilityScore(existing)
        ? incoming.severity
        : existing.severity,
    asset: incoming.cvss >= existing.cvss ? incoming.asset : existing.asset,
    summary: incoming.cvss >= existing.cvss ? incoming.summary : existing.summary,
  };
}

export function toCves(data: DashboardData): Cve[] {
  const map = new Map<string, Cve>();

  for (const record of data.cveRecords) {
    if (!isRealCveId(record.cve.id)) continue;

    const cvss = record.cve.score;
    const existing = map.get(record.cve.id);
    const ports = record.port ? [record.port] : record.cve.port ? [record.cve.port] : [];
    const incoming: Cve = {
      id: record.cve.id,
      cvss,
      severity: sourceSeverityToUi(record.cve.severity) ?? cvssToSeverity(cvss),
      threatType: inferThreatType(record.cve.summary ?? record.cve.id),
      ports,
      transport: transportForRecord(record, data),
      summary: record.cve.summary ?? `${record.cve.id} on ${record.ip}`,
      asset: record.ip,
      publishedAt: record.cve.publishedDate || data.lastUpdated,
      exploitKnown: Boolean(record.cve.kev),
      epss: record.cve.epss,
      verified: Boolean(record.verified ?? record.cve.verified),
      instanceCount: 1,
      affectedAssets: [record.ip],
    };

    if (!existing) {
      map.set(record.cve.id, incoming);
      continue;
    }

    map.set(record.cve.id, mergeCve(existing, incoming));
  }

  return [...map.values()].sort(
    (a, b) => exploitabilityScore(b) - exploitabilityScore(a) || b.cvss - a.cvss,
  );
}

export function toIpRecords(data: DashboardData): IpRecord[] {
  return data.ips
    .map((ip) => {
      const criticalCount = ip.cves.filter((c) => cvssToSeverity(c.score) === 'critical').length;
      const highCount = ip.cves.filter((c) => cvssToSeverity(c.score) === 'high').length;
      const maxCvss = ip.cves.length ? Math.max(...ip.cves.map((c) => c.score)) : 0;

      const code = normalizeCountryCode(ip.country);

      return {
        address: ip.ip,
        hostname: ip.hostnames[0] || ip.domains?.[0] || ip.organization || ip.ip,
        country: code ? countryLabel(code) : undefined,
        countryCode: code ?? undefined,
        city: ip.city,
        cveCount: ip.cves.length,
        criticalCount,
        highCount,
        maxCvss,
        cveIds: ip.cves.map((c) => c.id),
        serviceCount: Math.max(ip.services.length, ip.ports.length),
        lastScanAt: ip.lastSeen || ip.timestamp || data.lastUpdated,
        domains: ip.domains,
        hostStatus: ip.hostStatus,
        openPortCount: ip.openPorts.length,
        operatingSystem: ip.operatingSystem,
        asn: ip.asn,
        isp: ip.isp,
        services: ip.services,
        scanTypes: ip.scanTypes,
      };
    })
    .sort((a, b) => b.maxCvss - a.maxCvss || b.cveCount - a.cveCount);
}

export function toSolutions(cves: Cve[]): CveSolution[] {
  return cves
    .filter((c) => c.severity === 'critical' || c.severity === 'high')
    .sort(compareSolutionPriority)
    .map((cve) => ({
      id: `sol-${cve.id}`,
      cveId: cve.id,
      title: `Remediate ${cve.id} on ${cve.asset}`,
      description: cve.summary,
      status: cve.exploitKnown ? ('triage' as const) : ('open' as const),
      effort: cve.cvss >= 9 ? ('high' as const) : ('medium' as const),
      vendorFixAvailable: false,
    }));
}

function pickObservationFallback(data: DashboardData): RiskTrendView {
  const scanSources = buildScanSourceData(data);
  if (scanSources.length > 0) {
    return {
      variant: 'scan-sources',
      title: 'Scan sources',
      subtitle: 'Single observation window — where findings in this snapshot originated.',
      points: scanSources.map((source) => ({ label: source.name, value: source.count })),
    };
  }

  const ports = buildChartData(data).portHeatmap.slice(0, 8);
  if (ports.length > 0) {
    return {
      variant: 'ports',
      title: 'Findings by port',
      subtitle: 'Single observation window — breakdown by affected port.',
      points: ports.map((entry) => ({ label: entry.port, value: entry.count })),
    };
  }

  const signals = buildExploitabilitySignals(data);
  if (signals.length > 0) {
    return {
      variant: 'exploitability',
      title: 'Exploitability signals',
      subtitle: 'Single observation window — active risk indicators in this snapshot.',
      points: signals,
    };
  }

  return {
    variant: 'timeline',
    title: 'Observation timeline',
    subtitle: 'Not enough dated observations to chart a trend or breakdown.',
    points: [],
  };
}

export function toRiskTrendView(data: DashboardData): RiskTrendView {
  const datedRecords: Date[] = [];

  for (const record of data.cveRecords) {
    const date = parseDate(record.cve.publishedDate);
    if (date) datedRecords.push(date);
  }

  if (datedRecords.length === 0) {
    return pickObservationFallback(data);
  }

  const dayBuckets = new Map<string, number>();
  for (const date of datedRecords) {
    const dayKey = toDayKey(date);
    dayBuckets.set(dayKey, (dayBuckets.get(dayKey) ?? 0) + 1);
  }

  if (dayBuckets.size >= 2) {
    const points = [...dayBuckets.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-14)
      .map(([dayKey, value]) => ({
        label: formatShortDay(dayKey),
        value,
      }));

    return {
      variant: 'timeline',
      title: 'Observation timeline',
      subtitle: 'Findings grouped by observation day from scan timestamps.',
      points,
    };
  }

  const hourBuckets = new Map<number, number>();
  for (const date of datedRecords) {
    hourBuckets.set(date.getHours(), (hourBuckets.get(date.getHours()) ?? 0) + 1);
  }

  if (hourBuckets.size >= 2) {
    const dayKey = [...dayBuckets.keys()][0];
    const points = [...hourBuckets.entries()]
      .sort(([a], [b]) => a - b)
      .map(([hour, value]) => ({
        label: formatHourLabel(hour),
        value,
      }));

    return {
      variant: 'hourly',
      title: 'Observations by hour',
      subtitle: `Findings observed on ${formatDayKey(dayKey)}.`,
      points,
    };
  }

  return pickObservationFallback(data);
}

export function toVendorsAndProducts(data: DashboardData): {
  vendors: VendorRisk[];
  products: ProductRisk[];
} {
  const productMap = new Map<
    string,
    { name: string; version?: string; cveIds: Set<string>; maxCvss: number }
  >();

  for (const record of data.cveRecords) {
    const product = record.product ?? record.cve.product;
    if (!product) continue;

    const ip = data.ips.find((item) => item.ip === record.ip);
    const productIndex = ip?.products.indexOf(product) ?? -1;
    const version = productIndex >= 0 ? ip?.versions[productIndex] : undefined;

    const key = `${product}::${version ?? ''}`;
    const entry = productMap.get(key) ?? {
      name: product,
      version,
      cveIds: new Set<string>(),
      maxCvss: 0,
    };
    entry.cveIds.add(record.cve.id);
    entry.maxCvss = Math.max(entry.maxCvss, record.cve.score);
    productMap.set(key, entry);
  }

  const vendorAgg = new Map<
    string,
    { name: string; products: Set<string>; cveIds: Set<string>; criticalCount: number; maxScore: number }
  >();

  const products: ProductRisk[] = [];

  for (const [key, entry] of productMap) {
    const vendorName = entry.name.split(/[\/\s]/)[0] || entry.name;
    const vendorId = slugify(vendorName);
    const productId = slugify(key);

    products.push({
      id: productId,
      vendorId,
      name: entry.name,
      version: entry.version,
      cveCount: entry.cveIds.size,
      maxCvss: entry.maxCvss,
      cveIds: [...entry.cveIds],
    });

    const vendor = vendorAgg.get(vendorId) ?? {
      name: vendorName,
      products: new Set<string>(),
      cveIds: new Set<string>(),
      criticalCount: 0,
      maxScore: 0,
    };
    vendor.products.add(productId);
    for (const id of entry.cveIds) vendor.cveIds.add(id);
    if (entry.maxCvss >= 9) vendor.criticalCount += 1;
    vendor.maxScore = Math.max(vendor.maxScore, entry.maxCvss);
    vendorAgg.set(vendorId, vendor);
  }

  const vendors: VendorRisk[] = [...vendorAgg.entries()]
    .map(([id, v]) => ({
      id,
      name: v.name,
      riskScore: Math.min(100, Math.round(v.maxScore * 10)),
      productCount: v.products.size,
      cveCount: v.cveIds.size,
      criticalCount: v.criticalCount,
    }))
    .sort((a, b) => b.riskScore - a.riskScore);

  return { vendors, products: products.sort((a, b) => b.maxCvss - a.maxCvss) };
}

export interface DerivedData {
  cves: Cve[];
  ips: IpRecord[];
  solutions: CveSolution[];
  riskTrendView: RiskTrendView;
  vendors: VendorRisk[];
  products: ProductRisk[];
}

export function deriveDashboardViews(data: DashboardData): DerivedData {
  const cves = toCves(data);
  const ips = toIpRecords(data);
  const { vendors, products } = toVendorsAndProducts(data);

  return {
    cves,
    ips,
    solutions: toSolutions(cves),
    riskTrendView: toRiskTrendView(data),
    vendors,
    products,
  };
}
