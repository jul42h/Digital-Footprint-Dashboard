import { apiUrl } from "@/lib/api";
import { sanitizeAiText } from "./sanitizeAiText";
import type {
  AnalysisFinding,
  AnalysisIntent,
  AnalysisMode,
  CveAnalysisResponse,
} from "./types";
import { intentFromMode, modeFromIntent, MAX_CVE_IDS_PAYLOAD, MAX_FINDINGS_PER_REQUEST } from "./types";

const MEMORY = new Map<string, { savedAt: number; data: CveAnalysisResponse }>();
const STORAGE_KEY = "df-cve-analysis-cache-v7";
const BRIEF_SIGNAL_KEY = "df-home-brief-signal-v4";

/** Home brief auto-refreshes at most every 2 hours unless priority signals change. */
export const BRIEF_REFRESH_MS = 2 * 60 * 60 * 1000;
const DETAIL_TTL_MS = 30 * 60 * 1000;

/** Whole-system views (like `brief`) reflect the full dataset, not one CVE selection —
 * refresh on the same cadence rather than the shorter per-selection detail TTL. */
const BRIEF_LIKE_INTENTS = new Set<AnalysisIntent>([
  "brief",
  "insights",
  "risk_score",
  "threat_intel",
  "critical_findings",
  "risk_assets",
]);

type StoredEntry = { savedAt: number; data: CveAnalysisResponse };
type StoredCache = Record<string, StoredEntry>;

function ttlForIntent(intent: AnalysisIntent): number {
  return BRIEF_LIKE_INTENTS.has(intent) ? BRIEF_REFRESH_MS : DETAIL_TTL_MS;
}

function parseErrorDetail(text: string, status: number): string {
  try {
    const parsed = JSON.parse(text) as { detail?: unknown; error?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
    if (typeof parsed.error === "string") return parsed.error;
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
  if (String(data.status || "").toLowerCase() === "error") {
    throw new Error(data.error || data.reason || "Analysis failed");
  }
  const cleaned = sanitizeAiText(data.ai_summary);
  if (cleaned) return { ...data, ai_summary: cleaned };
  if (data.reason?.trim()) {
    throw new Error(data.reason.trim());
  }
  const status = (data.status || "").toLowerCase();
  if (status && !["ok", "success", "completed", "analyzed"].includes(status)) {
    throw new Error(`Analysis status: ${data.status}`);
  }
  throw new Error("Analysis completed with no summary returned.");
}

export function cacheKey(cveIds: string[], intent: AnalysisIntent): string {
  return `${intent}:${[...cveIds].map((id) => id.toUpperCase()).sort().join(",")}`;
}

/** Fingerprint for major change — top CVEs or their KEV/severity shifted. */
export function briefSignalKey(
  items: Array<{ id: string; severity: string; exploitKnown?: boolean }>,
): string {
  return items
    .map((c) => `${c.id.toUpperCase()}:${c.severity}:${c.exploitKnown ? "1" : "0"}`)
    .join("|");
}

function priorityStorageKey(cveIds: string[]): string {
  return [...cveIds].map((id) => id.toUpperCase()).sort().join("|");
}

function readStored(): StoredCache {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as StoredCache;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeStored(cache: StoredCache): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cache));
  } catch {
    /* ignore */
  }
}

function getCachedEntry(key: string, intent: AnalysisIntent): StoredEntry | null {
  const mem = MEMORY.get(key);
  if (mem) {
    if (Date.now() - mem.savedAt > ttlForIntent(intent)) {
      MEMORY.delete(key);
    } else {
      return mem;
    }
  }

  const stored = readStored();
  const entry = stored[key];
  if (!entry) return null;
  if (Date.now() - entry.savedAt > ttlForIntent(intent)) {
    delete stored[key];
    writeStored(stored);
    return null;
  }
  MEMORY.set(key, entry);
  return entry;
}

function setCached(key: string, data: CveAnalysisResponse): void {
  const entry = { savedAt: Date.now(), data };
  MEMORY.set(key, entry);
  const stored = readStored();
  stored[key] = entry;
  const now = Date.now();
  for (const [k, e] of Object.entries(stored)) {
    const intent = (k.split(":")[0] || "insights") as AnalysisIntent;
    if (now - e.savedAt > ttlForIntent(intent)) delete stored[k];
  }
  writeStored(stored);
}

export function peekCachedAnalysis(
  cveIds: string[],
  intent: AnalysisIntent,
): CveAnalysisResponse | null {
  return getCachedEntry(cacheKey(cveIds, intent), intent)?.data ?? null;
}

export function peekCachedAnalysisMeta(
  cveIds: string[],
  intent: AnalysisIntent,
): { data: CveAnalysisResponse; savedAt: number; ageMs: number } | null {
  const entry = getCachedEntry(cacheKey(cveIds, intent), intent);
  if (!entry) return null;
  return { data: entry.data, savedAt: entry.savedAt, ageMs: Date.now() - entry.savedAt };
}

function readBriefSignal(priorityKey: string): string | null {
  try {
    const raw = localStorage.getItem(BRIEF_SIGNAL_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { priorityKey: string; signalKey: string };
    if (parsed.priorityKey !== priorityKey) return null;
    return parsed.signalKey;
  } catch {
    return null;
  }
}

export function rememberBriefSignal(cveIds: string[], signalKey: string): void {
  try {
    localStorage.setItem(
      BRIEF_SIGNAL_KEY,
      JSON.stringify({
        priorityKey: priorityStorageKey(cveIds),
        signalKey,
        savedAt: Date.now(),
      }),
    );
  } catch {
    /* ignore */
  }
}

export function shouldAutoRefreshBrief(
  cveIds: string[],
  signalKey: string,
): { refresh: boolean; reason: "missing" | "changed" | "stale" | "fresh"; ageMs: number } {
  const priorityKey = priorityStorageKey(cveIds);
  const meta = peekCachedAnalysisMeta(cveIds, "brief");
  if (!meta) return { refresh: true, reason: "missing", ageMs: 0 };

  const storedSignal = readBriefSignal(priorityKey);
  if (!storedSignal || storedSignal !== signalKey) {
    return { refresh: true, reason: "changed", ageMs: meta.ageMs };
  }

  if (meta.ageMs >= BRIEF_REFRESH_MS) {
    return { refresh: true, reason: "stale", ageMs: meta.ageMs };
  }

  return { refresh: false, reason: "fresh", ageMs: meta.ageMs };
}

export async function analyzeCves(
  cveIds: string[],
  options: {
    intent?: AnalysisIntent;
    /** @deprecated use intent */
    mode?: AnalysisMode;
    findings?: AnalysisFinding[];
    bypassCache?: boolean;
  } = {},
): Promise<CveAnalysisResponse> {
  const intent =
    options.intent ?? (options.mode ? intentFromMode(options.mode) : "insights");
  const mode = modeFromIntent(intent);
  const ids = [...cveIds].map((id) => id.toUpperCase()).filter(Boolean);
  const key = cacheKey(ids, intent);
  if (!options.bypassCache) {
    const hit = getCachedEntry(key, intent)?.data;
    if (hit) return hit;
  }

  // Prefer findings; cve_ids remain as fallback / identity for cache and Lambda echo.
  const body: Record<string, unknown> = {
    intent,
    mode, // legacy alias; Lambda uses intent when present
    cve_ids: ids.slice(0, MAX_CVE_IDS_PAYLOAD),
  };
  if (options.findings?.length) {
    // Drop empty optional fields so the payload matches Lambda FINDING_FIELDS.
    body.findings = options.findings.slice(0, MAX_FINDINGS_PER_REQUEST).map((finding) =>
      Object.fromEntries(
        Object.entries(finding).filter(([, value]) => value !== undefined && value !== ""),
      ),
    );
  }

  const response = await fetch(apiUrl("/api/cve-analysis"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(parseErrorDetail(detail, response.status));
  }
  const data = assertUsableResult((await response.json()) as CveAnalysisResponse);
  setCached(key, data);
  return data;
}

/** Free-text question over whole-dashboard data (intent="ask_ai"). No CVE selection required. */
export async function askAi(
  question: string,
  options: {
    findings?: AnalysisFinding[];
    cveIds?: string[];
    bypassCache?: boolean;
  } = {},
): Promise<CveAnalysisResponse> {
  const trimmed = question.trim();
  if (!trimmed) throw new Error("A question is required.");

  const ids = [...(options.cveIds ?? [])].map((id) => id.toUpperCase()).filter(Boolean);
  const key = `ask_ai:${trimmed.toLowerCase()}`;
  if (!options.bypassCache) {
    const hit = getCachedEntry(key, "ask_ai")?.data;
    if (hit) return hit;
  }

  const body: Record<string, unknown> = { intent: "ask_ai", mode: "detail", question: trimmed };
  if (ids.length) body.cve_ids = ids.slice(0, MAX_CVE_IDS_PAYLOAD);
  if (options.findings?.length) {
    body.findings = options.findings.slice(0, MAX_FINDINGS_PER_REQUEST).map((finding) =>
      Object.fromEntries(
        Object.entries(finding).filter(([, value]) => value !== undefined && value !== ""),
      ),
    );
  }

  const response = await fetch(apiUrl("/api/cve-analysis"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(parseErrorDetail(detail, response.status));
  }
  const data = assertUsableResult((await response.json()) as CveAnalysisResponse);
  setCached(key, data);
  return data;
}
