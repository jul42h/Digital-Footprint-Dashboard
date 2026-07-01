import type { SolutionStatus as Status } from "@/types";

const LABEL: Record<Status, string> = {
  open: "Not started",
  triage: "Under review",
  assigned: "In progress",
  resolved: "Done",
};

export function SolutionStatus({ status }: { status: Status }) {
  return <span className={`status status--${status}`}>{LABEL[status]}</span>;
}
