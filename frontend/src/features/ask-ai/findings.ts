import type { Cve } from "@/types";
import type { CVEFlatRecord, DashboardData, SourceIPRecord } from "@/types/data";
import type { AnalysisFinding } from "./types";
import { MAX_FINDINGS_PER_REQUEST } from "./types";

function numStr(value: number | null | undefined): string | undefined {
  if (value == null || !Number.isFinite(value)) return undefined;
  return String(value);
}

function versionForProduct(ip: SourceIPRecord | undefined, product: string | undefined): string | undefined {
  if (!ip || !product) return undefined;
  const idx = ip.products.indexOf(product);
  if (idx < 0) return undefined;
  return ip.versions[idx] || undefined;
}

/** Map one dashboard flat record → Lambda finding (vital fields only). */
export function findingFromRecord(
  record: CVEFlatRecord,
  ipLookup?: Map<string, SourceIPRecord>,
): AnalysisFinding {
  const ip = ipLookup?.get(record.ip);
  const product = record.product ?? record.cve.product;
  const service = record.service ?? record.cve.service;
  const port = record.port ?? record.cve.port;
  const epss = record.cve.epss ?? record.cve.rankingEpss;
  const rankingEpss = record.cve.rankingEpss;

  return {
    cve_id: record.cve.id.toUpperCase(),
    ip: record.ip || undefined,
    cvss: numStr(record.cve.score),
    epss: numStr(epss),
    ranking_epss: numStr(rankingEpss),
    kev: Boolean(record.cve.kev),
    verified: Boolean(record.verified ?? record.cve.verified),
    summary: record.cve.summary || undefined,
    port: port != null ? String(port) : undefined,
    protocol: ip?.transport?.[0]?.toLowerCase(),
    transport: ip?.transport?.[0]?.toLowerCase(),
    service_name: service || undefined,
    product: product || undefined,
    version: versionForProduct(ip, product),
    domains: ip?.domains?.length ? ip.domains.join(", ") : undefined,
    hostnames: ip?.hostnames?.length ? ip.hostnames.join(", ") : undefined,
    os: record.operatingSystem || ip?.operatingSystem || undefined,
  };
}

function findingFromCve(cve: Cve, assetOverride?: string): AnalysisFinding {
  return {
    cve_id: cve.id.toUpperCase(),
    ip: assetOverride || cve.asset || undefined,
    cvss: numStr(cve.cvss),
    epss: numStr(cve.epss),
    kev: Boolean(cve.exploitKnown),
    verified: cve.verified,
    summary: cve.summary || undefined,
    port: cve.ports[0] != null ? String(cve.ports[0]) : undefined,
    protocol: cve.transport ? cve.transport.toLowerCase() : undefined,
    transport: cve.transport ? cve.transport.toLowerCase() : undefined,
    hostnames: cve.affectedAssets?.length ? cve.affectedAssets.join(", ") : undefined,
  };
}

/** Rank flat records like the Lambda: KEV > EPSS > CVSS > verified. */
export function rankFindingRecords(records: CVEFlatRecord[]): CVEFlatRecord[] {
  return [...records].sort((a, b) => {
    const kev = Number(Boolean(b.cve.kev)) - Number(Boolean(a.cve.kev));
    if (kev !== 0) return kev;
    const aEpss = a.cve.epss ?? a.cve.rankingEpss ?? -1;
    const bEpss = b.cve.epss ?? b.cve.rankingEpss ?? -1;
    if (bEpss !== aEpss) return bEpss - aEpss;
    if (b.cve.score !== a.cve.score) return b.cve.score - a.cve.score;
    return (
      Number(Boolean(b.verified ?? b.cve.verified)) -
      Number(Boolean(a.verified ?? a.cve.verified))
    );
  });
}

/**
 * Build Lambda `findings` from dashboard flat records (preferred).
 * When `preferCveIds` is set, those CVE instances are ordered first for cache /
 * focus identity; Lambda still re-ranks.
 */
export function toAnalysisFindingsFromData(
  data: DashboardData,
  options: {
    preferCveIds?: string[];
    onlyCveIds?: string[];
    limit?: number;
  } = {},
): AnalysisFinding[] {
  const limit = options.limit ?? MAX_FINDINGS_PER_REQUEST;
  const ipLookup = new Map(data.ips.map((ip) => [ip.ip, ip]));
  const only = options.onlyCveIds?.map((id) => id.toUpperCase());
  const prefer = new Set((options.preferCveIds ?? []).map((id) => id.toUpperCase()));

  let records = data.cveRecords.filter((record) => {
    const id = record.cve.id?.toUpperCase();
    if (!id?.startsWith("CVE-")) return false;
    if (only && !only.includes(id)) return false;
    return true;
  });

  records = rankFindingRecords(records);

  if (prefer.size) {
    const focus: CVEFlatRecord[] = [];
    const rest: CVEFlatRecord[] = [];
    for (const record of records) {
      if (prefer.has(record.cve.id.toUpperCase())) focus.push(record);
      else rest.push(record);
    }
    records = [...focus, ...rest];
  }

  const out: AnalysisFinding[] = [];
  for (const record of records) {
    if (out.length >= limit) break;
    out.push(findingFromRecord(record, ipLookup));
  }
  return out;
}

/** Fallback when only UI `Cve` rows exist (e.g. unit tests). */
export function toAnalysisFindings(
  cves: Cve[],
  limit: number = MAX_FINDINGS_PER_REQUEST,
): AnalysisFinding[] {
  const out: AnalysisFinding[] = [];
  for (const cve of cves) {
    if (out.length >= limit) break;
    out.push(findingFromCve(cve));
  }
  return out;
}

export function findingsForCveIds(allCves: Cve[], cveIds: string[]): AnalysisFinding[] {
  const byId = new Map(allCves.map((cve) => [cve.id.toUpperCase(), cve]));
  const ordered: Cve[] = [];
  for (const id of cveIds) {
    const cve = byId.get(id.toUpperCase());
    if (cve) ordered.push(cve);
  }
  return toAnalysisFindings(ordered);
}
