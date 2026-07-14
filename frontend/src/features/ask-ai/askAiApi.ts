import { apiUrl } from "@/lib/api";
import type { AnalysisMode, CveAnalysisResponse } from "./types";

const MEMORY = new Map<string, CveAnalysisResponse>();
const STORAGE_KEY = "df-cve-analysis-cache-v1";
/** Avoid re-paying Lambda for the same CVE set within a browser session window. */
const CACHE_TTL_MS = 30 * 60 * 1000;

type StoredEntry = { savedAt: number; data: CveAnalysisResponse };
type StoredCache = Record<string, StoredEntry>;

function parseErrorDetail(text: string, status: number): string {
  try {
    const parsed = JSON.parse(text) as { detail?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
    if (Array.isArray(parsed.detail)) {
      return parsed.detail
        .map((item) =>
          typeof item === "object" && item && "msg" in item
            ? String((item as { msg: string }).msg)
            : String(item),
        )
        .join("; ");
    }
  } catch {
    /* use raw text */
  }
  return text || `CVE analysis failed (${status})`;
}

function assertUsableResult(data: CveAnalysisResponse): CveAnalysisResponse {
  if (data.ai_summary?.trim()) return data;
  if (data.reason?.trim()) {
    throw new Error(data.reason.trim());
  }
  const status = (data.status || "").toLowerCase();
  if (status && !["ok", "success", "completed", "analyzed"].includes(status)) {
    throw new Error(`Analysis status: ${data.status}`);
  }
  throw new Error("Analysis completed with no summary returned.");
}

export function cacheKey(cveIds: string[], mode: AnalysisMode): string {
  return `${mode}:${[...cveIds].map((id) => id.toUpperCase()).sort().join(",")}`;
}

function readStored(): StoredCache {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as StoredCache;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeStored(cache: StoredCache): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(cache));
  } catch {
    /* quota / private mode — memory cache still works */
  }
}

function getCached(key: string): CveAnalysisResponse | null {
  const mem = MEMORY.get(key);
  if (mem) return mem;

  const stored = readStored();
  const entry = stored[key];
  if (!entry) return null;
  if (Date.now() - entry.savedAt > CACHE_TTL_MS) {
    delete stored[key];
    writeStored(stored);
    return null;
  }
  MEMORY.set(key, entry.data);
  return entry.data;
}

function setCached(key: string, data: CveAnalysisResponse): void {
  MEMORY.set(key, data);
  const stored = readStored();
  stored[key] = { savedAt: Date.now(), data };
  // Drop expired keys while writing
  const now = Date.now();
  for (const [k, entry] of Object.entries(stored)) {
    if (now - entry.savedAt > CACHE_TTL_MS) delete stored[k];
  }
  writeStored(stored);
}

export function peekCachedAnalysis(
  cveIds: string[],
  mode: AnalysisMode,
): CveAnalysisResponse | null {
  return getCached(cacheKey(cveIds, mode));
}

export function clearAnalysisCache(): void {
  MEMORY.clear();
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export async function analyzeCves(
  cveIds: string[],
  options: { mode?: AnalysisMode; bypassCache?: boolean } = {},
): Promise<CveAnalysisResponse> {
  const mode = options.mode ?? "detail";
  const key = cacheKey(cveIds, mode);
  if (!options.bypassCache) {
    const hit = getCached(key);
    if (hit) return hit;
  }

  const response = await fetch(apiUrl("/api/cve-analysis"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cve_ids: cveIds, mode }),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(parseErrorDetail(detail, response.status));
  }
  const data = assertUsableResult((await response.json()) as CveAnalysisResponse);
  setCached(key, data);
  return data;
}
