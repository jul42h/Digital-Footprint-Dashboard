import { CveTable } from "./CveTable";
import { PageHeader } from "@/components/PageHeader";
import { NAV_LABELS } from "@/lib/copy";

export function CvesPage() {
  return (
    <div className="page">
      <PageHeader
        title={NAV_LABELS.issues}
        subtitle="Every security issue we found, ordered by risk. Select one to read what it means and how to fix it."
      />
      <CveTable title="All issues" />
    </div>
  );
}
