import type { QuickAction } from "./types";

export const QUICK_ACTIONS: QuickAction[] = [
  {
    id: "summarize",
    label: "Summarize Today's Findings",
    prompt: "Summarize today's findings across our external footprint.",
  },
  {
    id: "patch",
    label: "What Should I Patch First?",
    prompt: "What should I patch first based on KEV, EPSS, CVSS, and asset exposure?",
  },
  {
    id: "assets",
    label: "Highest Risk Assets",
    prompt: "Which assets are highest risk right now and why?",
  },
  {
    id: "cve",
    label: "Explain This CVE",
    prompt: "Explain the most critical CVE in our environment and which assets it affects.",
  },
  {
    id: "host",
    label: "Explain This Host",
    prompt: "Explain our highest-risk host: open ports, services, CVEs, and remediation priorities.",
  },
  {
    id: "facing",
    label: "Show Internet-Facing Assets",
    prompt: "Show internet-facing assets and highlight the most exposed ones.",
  },
  {
    id: "mitigate",
    label: "Recommend Mitigations",
    prompt: "Recommend mitigations for our highest-priority vulnerabilities.",
  },
  {
    id: "score",
    label: "Explain the Current Risk Score",
    prompt: "Why is the current risk score so high? Break down the contributing factors.",
  },
];
