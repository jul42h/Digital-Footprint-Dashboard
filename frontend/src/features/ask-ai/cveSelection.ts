import type { Cve } from "@/types";

const SEVERITY_RANK: Record<Cve["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Prioritize KEV, then severity, then CVSS. */
export function pickPriorityCves(cves: Cve[], limit = 5): Cve[] {
  return [...cves]
    .sort((a, b) => {
      const kev = Number(Boolean(b.exploitKnown)) - Number(Boolean(a.exploitKnown));
      if (kev !== 0) return kev;
      const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (sev !== 0) return sev;
      return b.cvss - a.cvss;
    })
    .slice(0, limit);
}

export function pickPriorityCveIds(cves: Cve[], limit = 5): string[] {
  return pickPriorityCves(cves, limit).map((c) => c.id);
}

export function pickKevCveIds(cves: Cve[], limit = 5): string[] {
  return [...cves]
    .filter((c) => c.exploitKnown)
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, limit)
    .map((c) => c.id);
}

const CVE_ID_RE = /CVE-\d{4}-\d+/gi;

export function extractCveIds(text: string): string[] {
  const matches = text.match(CVE_ID_RE) ?? [];
  const seen = new Set<string>();
  const ids: string[] = [];
  for (const match of matches) {
    const id = match.toUpperCase();
    if (seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

export function normalizeCveId(raw: string): string | null {
  const trimmed = raw.trim().toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(trimmed)) return trimmed;
  return null;
}

/**
 * Home brief display trim when Lambda returns too much text.
 * Aims for ~2–3 descriptive sentences (not a one-liner, not a full essay).
 */
export function toBriefPreview(text: string, maxChars = 420): { preview: string; truncated: boolean } {
  const cleaned = text.replace(/\s+/g, " ").trim();
  if (!cleaned) return { preview: cleaned, truncated: false };

  const sentences = cleaned.match(/[^.!?]+[.!?]+(?:\s|$)/g);
  if (sentences?.length) {
    let out = sentences[0].trim();
    if (sentences[1]) out = `${out} ${sentences[1].trim()}`;
    if (sentences[2] && out.length < 280) out = `${out} ${sentences[2].trim()}`;
    if (out.length <= maxChars) {
      return { preview: out, truncated: out.length < cleaned.length };
    }
    return {
      preview: `${out.slice(0, maxChars).replace(/\s+\S*$/, "")}…`,
      truncated: true,
    };
  }

  if (cleaned.length <= maxChars) return { preview: cleaned, truncated: false };
  return {
    preview: `${cleaned.slice(0, maxChars).replace(/\s+\S*$/, "")}…`,
    truncated: true,
  };
}
