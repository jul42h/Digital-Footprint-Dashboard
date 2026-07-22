import type { AnalysisIntent } from "./types";

/**
 * Guided Ask AI chips. Prompt text for these ids lives in the Lambda
 * (`ASK_AI_PRESETS` / `ASK_AI_TEMPLATES`) — the dashboard only sends ids + labels.
 */
interface GuidedQuestion {
  id: string;
  /** Button label, kept short. */
  label: string;
}

interface GuidedQuestionGroup {
  id: string;
  label: string;
  items: GuidedQuestion[];
}

/** Follow-up chip: ask a predetermined question, or run a remediation plan. */
export type FollowUpAction =
  | {
      id: string;
      kind: "ask";
      label: string;
      questionId: string;
      params?: Record<string, string>;
    }
  | { id: string; kind: "remediate"; label: string; cveIds?: string[] };

export const GUIDED_QUESTION_GROUPS: GuidedQuestionGroup[] = [
  {
    id: "decide",
    label: "Decide what to do",
    items: [
      { id: "fix-first", label: "What should we fix first?" },
      { id: "quick-wins", label: "Fastest risk reduction" },
      { id: "validate-first", label: "What should we validate first?" },
    ],
  },
  {
    id: "understand",
    label: "Understand the evidence",
    items: [
      { id: "risk-score-drivers", label: "What's driving the risk score?" },
      { id: "active-exploitation", label: "Which issues are known exploited?" },
      { id: "evidence-gaps", label: "Where are the evidence gaps?" },
    ],
  },
  {
    id: "communicate",
    label: "Communicate risk",
    items: [
      { id: "leadership-summary", label: "Explain for leadership" },
    ],
  },
];

const ALL_GUIDED = GUIDED_QUESTION_GROUPS.flatMap((group) => group.items);

function guidedById(id: string): GuidedQuestion | undefined {
  return ALL_GUIDED.find((q) => q.id === id);
}

/** Optional next-step prompts after an assistant answer. */
export function pickFollowUpActions(options: {
  lastUserContent?: string;
  cveIds?: string[];
  intent?: AnalysisIntent | null;
  limit?: number;
}): FollowUpAction[] {
  const limit = options.limit ?? 3;
  const last = (options.lastUserContent ?? "").trim().toLowerCase();
  const cveIds = options.cveIds ?? [];
  const primaryCve = cveIds.length === 1 ? cveIds[0] : null;

  const candidates: FollowUpAction[] = [];

  if (primaryCve) {
    candidates.push(
      {
        id: `remediate-${primaryCve}`,
        kind: "remediate",
        label: "Remediation plan",
        cveIds: [primaryCve],
      },
      {
        id: `impact-${primaryCve}`,
        kind: "ask",
        label: "Operational exposure?",
        questionId: "cve-impact",
        params: { cve_id: primaryCve },
      },
      {
        id: `assets-${primaryCve}`,
        kind: "ask",
        label: "Which assets are affected?",
        questionId: "cve-assets",
        params: { cve_id: primaryCve },
      },
    );
  } else if (cveIds.length > 1) {
    candidates.push({
      id: "remediate-discussed",
      kind: "remediate",
      label: "Remediation plan",
      cveIds,
    });
  }

  // After a remediation plan, surface understanding-oriented questions rather
  // than "fix-first"/"quick-wins" (which just restate the plan's priority).
  const sharedIds =
    options.intent === "remediate"
      ? (["active-exploitation", "risk-score-drivers", "leadership-summary"] as const)
      : ([
          "fix-first",
          "quick-wins",
          "validate-first",
          "risk-score-drivers",
          "active-exploitation",
          "evidence-gaps",
          "leadership-summary",
        ] as const);

  for (const id of sharedIds) {
    const item = guidedById(id);
    if (!item) continue;
    candidates.push({
      id: item.id,
      kind: "ask",
      label: item.label,
      questionId: item.id,
    });
  }

  const seen = new Set<string>();
  const out: FollowUpAction[] = [];
  for (const item of candidates) {
    if (seen.has(item.id)) continue;
    if (item.kind === "ask") {
      const alreadyAsked =
        last &&
        (item.label.toLowerCase() === last ||
          item.questionId === last ||
          last.includes(item.label.toLowerCase().slice(0, 18)));
      if (alreadyAsked) continue;
    }
    if (item.kind === "remediate" && options.intent === "remediate") continue;
    seen.add(item.id);
    out.push(item);
    if (out.length >= limit) break;
  }
  return out;
}
