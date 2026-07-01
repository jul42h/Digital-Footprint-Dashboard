import { ViewAllLink } from "@/components/ViewAllLink";
import { SolutionTable } from "@/features/solutions/SolutionTable";
import { NAV_LABELS } from "@/lib/copy";

export function HomeRemediationQueue({ limit = 5 }: { limit?: number }) {
  return (
    <SolutionTable
      limit={limit}
      title={`Priority ${NAV_LABELS.fixes.toLowerCase()}`}
      showFilter={false}
      action={<ViewAllLink to="/solutions" />}
    />
  );
}
