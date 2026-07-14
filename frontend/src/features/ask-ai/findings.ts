import type { Cve } from "@/types";
import type { AnalysisFinding } from "./types";
import { MAX_FINDINGS_PER_REQUEST } from "./types";

function findingFromCve(cve: Cve, assetOverride?: string): AnalysisFinding {
  return {
    cve_id: cve.id.toUpperCase(),
    ip: assetOverride || cve.asset || undefined,
    cvss: Number.isFinite(cve.cvss) ? String(cve.cvss) : undefined,
    epss: cve.epss != null && Number.isFinite(cve.epss) ? String(cve.epss) : undefined,
    kev: Boolean(cve.exploitKnown),
    verified: cve.verified,
    summary: cve.summary || undefined,
    port: cve.ports[0] != null ? String(cve.ports[0]) : undefined,
    protocol: cve.transport ? cve.transport.toLowerCase() : undefined,
    transport: cve.transport ? cve.transport.toLowerCase() : undefined,
    hostnames: cve.affectedAssets?.length ? cve.affectedAssets.join(", ") : undefined,
  };
}

/** Map dashboard CVE records → Lambda `findings` (vital fields only). */
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
