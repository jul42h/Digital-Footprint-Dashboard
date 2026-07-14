/** Soft onboarding copy — kept short so tips stay non-invasive. */
export const QUICK_START_STORAGE_KEY = "df-quickstart-dismissed-v1";
export const ANALYZE_HINT_STORAGE_KEY = "df-analyze-hint-dismissed-v1";

export interface QuickStartStep {
  id: string;
  title: string;
  body: string;
  to: string;
}

export const QUICK_START_STEPS: QuickStartStep[] = [
  {
    id: "posture",
    title: "Scan the posture bar",
    body: "Critical, KEV, and risk score show whether you need to act today.",
    to: "/",
  },
  {
    id: "issues",
    title: "Open Security issues",
    body: "Filter by severity or known exploited (KEV) to focus the list.",
    to: "/cves",
  },
  {
    id: "fixes",
    title: "Track remediations",
    body: "Update status as work moves from triage to done.",
    to: "/solutions",
  },
  {
    id: "ai",
    title: "Optional: AI brief",
    body: "Generate a short priority brief on the home page, or use Analyze for a deeper write-up.",
    to: "/",
  },
];
