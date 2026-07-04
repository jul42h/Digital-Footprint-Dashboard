import type {
  Cve,
  CveSolution,
  IpRecord,
  ProductRisk,
  RiskPoint,
  SecurityAlert,
  VendorRisk,
} from '@/types';
import type { CVEFlatRecord, DashboardData } from '@/types/data';
import { inferThreatType } from '@/lib/inferThreat';
import { countryLabel, normalizeCountryCode } from '@/lib/geo';
import { cvssToSeverity } from '@/lib/severity';
import { parseDate } from '@/utils/dateUtils';
import { computeNetworkRiskScore } from '@/utils/summaryGenerator';

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

export function toCves(data: DashboardData): Cve[] {
  const map = new Map<string, Cve>();

  for (const record of data.cveRecords) {
    const cvss = record.cve.score;
    const existing = map.get(record.cve.id);
    const ports = record.port ? [record.port] : [];
    const cve: Cve = {
      id: record.cve.id,
      cvss,
      severity: cvssToSeverity(cvss),
      threatType: inferThreatType(record.cve.summary ?? record.cve.id),
      ports: existing ? [...new Set([...existing.ports, ...ports])] : ports,
      transport: transportForRecord(record, data),
      summary: record.cve.summary ?? `${record.cve.id} on ${record.ip}`,
      asset: record.ip,
      publishedAt: record.cve.publishedDate || data.lastUpdated,
      exploitKnown: Boolean(record.cve.kev) || cvss >= 9.0,
    };
    if (!existing || cve.cvss > existing.cvss) {
      map.set(record.cve.id, cve);
    }
  }

  return [...map.values()].sort((a, b) => b.cvss - a.cvss);
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
        hostname: ip.hostnames[0] || ip.organization || ip.ip,
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
      };
    })
    .sort((a, b) => b.maxCvss - a.maxCvss || b.cveCount - a.cveCount);
}

export function toSolutions(cves: Cve[]): CveSolution[] {
  return cves
    .filter((c) => c.severity === 'critical' || c.severity === 'high')
    .map((cve) => ({
      id: `sol-${cve.id}`,
      cveId: cve.id,
      title: `Remediate ${cve.id} on ${cve.asset}`,
      description: cve.summary,
      status: cve.exploitKnown ? ('triage' as const) : ('open' as const),
      effort: cve.cvss >= 9 ? ('high' as const) : ('medium' as const),
      vendorFixAvailable: true,
    }));
}

export function toAlerts(cves: Cve[]): SecurityAlert[] {
  return cves
    .filter((c) => c.severity === 'critical' || c.severity === 'high')
    .slice(0, 12)
    .map((cve) => ({
      id: `alert-${cve.id}-${cve.asset}`,
      message: `${cve.id}: ${cve.summary}`,
      severity: cve.severity,
      source: cve.asset,
      occurredAt: cve.publishedAt,
    }));
}

export function toRiskTrend(data: DashboardData): RiskPoint[] {
  const baseScore = computeNetworkRiskScore(data.stats);
  const dayBuckets = new Map<string, number[]>();

  for (const record of data.cveRecords) {
    const date = parseDate(record.cve.publishedDate);
    if (!date) continue;
    const key = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const weight = record.cve.score * 10;
    const bucket = dayBuckets.get(key) ?? [];
    bucket.push(weight);
    dayBuckets.set(key, bucket);
  }

  if (dayBuckets.size === 0) {
    const today = new Date();
    return Array.from({ length: 14 }, (_, i) => {
      const d = new Date(today);
      d.setDate(d.getDate() - (13 - i));
      return {
        date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        score: Math.round(baseScore * (0.85 + (i / 13) * 0.15)),
      };
    });
  }

  return [...dayBuckets.entries()]
    .map(([date, weights]) => ({
      date,
      score: Math.min(
        100,
        Math.round(weights.reduce((s, w) => s + w, 0) / Math.max(weights.length, 1)),
      ),
    }))
    .slice(-14);
}

export function toVendorsAndProducts(data: DashboardData): {
  vendors: VendorRisk[];
  products: ProductRisk[];
} {
  const productMap = new Map<
    string,
    { name: string; version?: string; cveIds: Set<string>; maxCvss: number }
  >();

  for (const ip of data.ips) {
    for (let i = 0; i < ip.products.length; i++) {
      const name = ip.products[i];
      if (!name) continue;
      const version = ip.versions[i];
      const key = `${name}::${version ?? ''}`;
      const entry = productMap.get(key) ?? {
        name,
        version,
        cveIds: new Set<string>(),
        maxCvss: 0,
      };
      for (const cve of ip.cves) {
        entry.cveIds.add(cve.id);
        entry.maxCvss = Math.max(entry.maxCvss, cve.score);
      }
      productMap.set(key, entry);
    }
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
  alerts: SecurityAlert[];
  riskTrend: RiskPoint[];
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
    alerts: toAlerts(cves),
    riskTrend: toRiskTrend(data),
    vendors,
    products,
  };
}
