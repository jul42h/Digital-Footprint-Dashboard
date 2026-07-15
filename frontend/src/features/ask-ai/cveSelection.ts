import type { Cve } from "@/types";

/**
 * How many top-ranked CVEs Home's compact views (AI brief signal, Top critical
 * findings table) key off. Purely a frontend display choice — the Lambda's
 * "brief" intent is whole-system now and has no equivalent constant of its own.
 */
export const DEFAULT_PRIORITY_COUNT = 5;

/** Prioritize KEV > EPSS > CVSS > verified (matches analyzer ranking). */
export function pickPriorityCves(cves: Cve[], limit = DEFAULT_PRIORITY_COUNT): Cve[] {
  return [...cves]
    .sort((a, b) => {
      const kev = Number(Boolean(b.exploitKnown)) - Number(Boolean(a.exploitKnown));
      if (kev !== 0) return kev;
      const epss = (b.epss ?? -1) - (a.epss ?? -1);
      if (epss !== 0) return epss;
      const cvss = b.cvss - a.cvss;
      if (cvss !== 0) return cvss;
      return Number(Boolean(b.verified)) - Number(Boolean(a.verified));
    })
    .slice(0, limit);
}

export function pickPriorityCveIds(cves: Cve[], limit = DEFAULT_PRIORITY_COUNT): string[] {
  return pickPriorityCves(cves, limit).map((c) => c.id);
}

export function pickKevCveIds(cves: Cve[], limit = DEFAULT_PRIORITY_COUNT): string[] {
  return [...cves]
    .filter((c) => c.exploitKnown)
    .sort((a, b) => {
      const epss = (b.epss ?? -1) - (a.epss ?? -1);
      if (epss !== 0) return epss;
      return b.cvss - a.cvss;
    })
    .slice(0, limit)
    .map((c) => c.id);
}

export function normalizeCveId(raw: string): string | null {
  const trimmed = raw.trim().toUpperCase();
  if (/^CVE-\d{4}-\d{4,7}$/.test(trimmed)) return trimmed;
  return null;
}
