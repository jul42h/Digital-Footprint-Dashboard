import { KpiCard } from "@/components/KpiCard";
import { PageHeader } from "@/components/PageHeader";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { SolutionTable } from "./SolutionTable";
import { useSolutions } from "./hooks";

export function SolutionsPage() {
  const solutions = useSolutions();
  const notStarted = solutions.filter((s) => s.status === "open").length;
  const inReview = solutions.filter((s) => s.status === "triage").length;
  const inProgress = solutions.filter((s) => s.status === "assigned").length;
  const done = solutions.filter((s) => s.status === "resolved").length;
  const withVendorFix = solutions.filter((s) => s.vendorFixAvailable).length;

  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.fixes}
        subtitle={HELP_TEXT.solutionsPage}
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Total remediations", value: String(solutions.length), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Not started", value: String(notStarted), tone: notStarted > 0 ? "high" : "neutral" }} />
        <KpiCard kpi={{ label: "Under review", value: String(inReview), tone: inReview > 0 ? "medium" : "neutral" }} />
        <KpiCard kpi={{ label: "In progress", value: String(inProgress), tone: "neutral" }} />
        <KpiCard kpi={{ label: "Completed", value: String(done), tone: "low" }} />
        <KpiCard kpi={{ label: "Vendor fixes", value: String(withVendorFix), tone: "neutral" }} />
      </div>

      <SolutionTable title={`All ${NAV_LABELS.fixes.toLowerCase()}`} />
    </div>
  );
}
