import { MAX_QUESTION_LENGTH } from "./types";

/**
 * Fixed question set for the Ask AI "Guided" tab. The dashboard intentionally
 * has no free-text input here — users pick one of these vetted questions
 * instead of typing anything, so every `ask_ai` request the model sees is one
 * this dashboard authored and reviewed, not arbitrary user text.
 */
export interface GuidedQuestion {
  id: string;
  /** Button label, kept short. */
  label: string;
  /** Exact text sent as the `question` — must stay answerable from dashboard data alone. */
  question: string;
}

export interface GuidedQuestionGroup {
  id: string;
  label: string;
  items: GuidedQuestion[];
}

export const GUIDED_QUESTION_GROUPS: GuidedQuestionGroup[] = [
  {
    id: "priority",
    label: "Priority & remediation",
    items: [
      {
        id: "fix-first",
        label: "What should we fix first?",
        question: "What should we fix first, and why?",
      },
      {
        id: "remediation-priority",
        label: "Highest-priority remediation",
        question: "What remediation has the highest priority right now?",
      },
    ],
  },
  {
    id: "risk",
    label: "Risk & assets",
    items: [
      {
        id: "highest-risk-assets",
        label: "Which assets are highest risk?",
        question: "Which assets are the highest risk right now, and why?",
      },
      {
        id: "risk-score-drivers",
        label: "What's driving the risk score?",
        question: "What is driving the current overall risk score?",
      },
    ],
  },
  {
    id: "threat",
    label: "Threat context",
    items: [
      {
        id: "active-exploitation",
        label: "Signs of active exploitation?",
        question: "Are there signs of active exploitation in this data?",
      },
      {
        id: "threat-intel",
        label: "Relevant threat intelligence",
        question: "What threat intelligence is relevant here?",
      },
    ],
  },
  {
    id: "leadership",
    label: "For leadership",
    items: [
      {
        id: "leadership-summary",
        label: "Summarize the top business risk",
        question:
          "Summarize the top business risk in plain language for a non-technical leadership audience.",
      },
    ],
  },
];

// Every question is sent as the Lambda's `question` field, which is capped at
// MAX_QUESTION_CHARS server-side — catch an over-long addition at dev time.
if (import.meta.env.DEV) {
  for (const group of GUIDED_QUESTION_GROUPS) {
    for (const item of group.items) {
      if (item.question.length > MAX_QUESTION_LENGTH) {
        console.warn(
          `Guided question "${item.id}" exceeds MAX_QUESTION_LENGTH (${MAX_QUESTION_LENGTH}).`,
        );
      }
    }
  }
}
