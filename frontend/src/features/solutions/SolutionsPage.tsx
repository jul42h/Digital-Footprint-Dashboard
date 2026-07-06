import { KpiCard } from "@/components/KpiCard";
import { PageHeader } from "@/components/PageHeader";
import { useRemediation } from "@/context/RemediationContext";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { SOLUTION_STATUS_ORDER } from "@/lib/remediationConfig";
import { SolutionTable } from "./SolutionTable";
import { useSolutions } from "./hooks";

export function SolutionsPage() {
  const solutions = useSolutions();
  const { getStatusLabel } = useRemediation();
  const withVendorFix = solutions.filter((s) => s.vendorFixAvailable).length;

  const statusCounts = SOLUTION_STATUS_ORDER.map((status) => ({
    status,
    label: getStatusLabel(status),
    count: solutions.filter((s) => s.status === status).length,
  }));

  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.fixes}
        subtitle={`${HELP_TEXT.solutionsPage} Use the Status dropdown on each row to update progress — no code changes needed.`}
      />

      <div className="kpi-strip">
        <KpiCard kpi={{ label: "Total remediations", value: String(solutions.length), tone: "neutral" }} />
        {statusCounts.map(({ status, label, count }) => (
          <KpiCard
            key={status}
            kpi={{
              label,
              value: String(count),
              tone:
                status === "open" && count > 0
                  ? "high"
                  : status === "triage" && count > 0
                    ? "medium"
                    : status === "resolved"
                      ? "low"
                      : "neutral",
            }}
          />
        ))}
        <KpiCard kpi={{ label: "Vendor fixes", value: String(withVendorFix), tone: "neutral" }} />
      </div>

      <SolutionTable title={`All ${NAV_LABELS.fixes.toLowerCase()}`} />
    </div>
  );
}
