import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { CveSolution, SolutionEffort, SolutionStatus } from "@/types";
import { Card } from "@/components/Card";
import { SortableTh } from "@/components/SortableTh";
import { FilterChip, TableToolbar } from "@/components/TableToolbar";
import { useTableState } from "@/hooks/useTableState";
import { LABELS } from "@/lib/copy";
import { SolutionStatus as StatusBadge } from "./SolutionStatus";
import { useSolutions } from "./hooks";

type StatusFilter = SolutionStatus | "all";
type EffortFilter = SolutionEffort | "all";
type VendorFixFilter = "all" | "available";
type SolutionSortKey = "cveId" | "title" | "status" | "effort" | "vendorFix";

const STATUS_ORDER: SolutionStatus[] = ["open", "triage", "assigned", "resolved"];

const STATUS_LABEL: Record<SolutionStatus, string> = {
  open: "Not started",
  triage: "Under review",
  assigned: "In progress",
  resolved: "Done",
};

const STATUS_RANK: Record<SolutionStatus, number> = {
  open: 0,
  triage: 1,
  assigned: 2,
  resolved: 3,
};

const EFFORT_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 };

interface SolutionTableProps {
  cveId?: string;
  limit?: number;
  title?: string;
  showFilter?: boolean;
  action?: React.ReactNode;
}

function searchSolution(solution: CveSolution, query: string): boolean {
  const haystack = [solution.cveId, solution.title, solution.description, solution.status, solution.effort].join(" ").toLowerCase();
  return haystack.includes(query);
}

function sortSolution(solution: CveSolution, key: SolutionSortKey): string | number {
  switch (key) {
    case "cveId":
      return solution.cveId;
    case "title":
      return solution.title;
    case "status":
      return STATUS_RANK[solution.status];
    case "effort":
      return EFFORT_RANK[solution.effort] ?? 0;
    case "vendorFix":
      return solution.vendorFixAvailable ? 1 : 0;
  }
}

export function SolutionTable({
  cveId,
  limit,
  title = "Remediations",
  showFilter = true,
  action,
}: SolutionTableProps) {
  const navigate = useNavigate();
  const all = useSolutions();
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [effortFilter, setEffortFilter] = useState<EffortFilter>("all");
  const [vendorFixFilter, setVendorFixFilter] = useState<VendorFixFilter>("all");

  const source = useMemo(() => {
    let list = cveId ? all.filter((s) => s.cveId === cveId) : all;
    if (statusFilter !== "all") list = list.filter((s) => s.status === statusFilter);
    if (effortFilter !== "all") list = list.filter((s) => s.effort === effortFilter);
    if (vendorFixFilter === "available") list = list.filter((s) => s.vendorFixAvailable);
    return list;
  }, [all, cveId, effortFilter, statusFilter, vendorFixFilter]);

  const { query, setQuery, sort, toggleSort, rows, total, shown } = useTableState<CveSolution, SolutionSortKey>({
    items: source,
    defaultSort: { key: "status", direction: "asc" },
    getSortValue: sortSolution,
    search: searchSolution,
    limit,
  });

  return (
    <Card title={title} action={action}>
      <TableToolbar
        query={query}
        onQueryChange={setQuery}
        shown={shown}
        total={total}
        placeholder="Search remediation, CVE, or status…"
        filters={
          showFilter ? (
            <>
              <FilterChip active={statusFilter === "all"} onClick={() => setStatusFilter("all")}>
                All statuses
              </FilterChip>
              {STATUS_ORDER.map((s) => (
                <FilterChip key={s} active={statusFilter === s} onClick={() => setStatusFilter(s)}>
                  {STATUS_LABEL[s]}
                </FilterChip>
              ))}
              <FilterChip active={effortFilter === "low"} onClick={() => setEffortFilter((v) => (v === "low" ? "all" : "low"))}>
                Low effort
              </FilterChip>
              <FilterChip active={effortFilter === "medium"} onClick={() => setEffortFilter((v) => (v === "medium" ? "all" : "medium"))}>
                Medium effort
              </FilterChip>
              <FilterChip active={effortFilter === "high"} onClick={() => setEffortFilter((v) => (v === "high" ? "all" : "high"))}>
                High effort
              </FilterChip>
              <FilterChip active={vendorFixFilter === "available"} onClick={() => setVendorFixFilter((v) => (v === "available" ? "all" : "available"))}>
                Vendor fix available
              </FilterChip>
            </>
          ) : undefined
        }
      />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              {!cveId && (
                <SortableTh label={LABELS.issueId} sortKey="cveId" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 132 }} />
              )}
              <SortableTh label="What to do" sortKey="title" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} />
              <SortableTh label={LABELS.status} sortKey="status" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 100 }} />
              <SortableTh label={LABELS.effort} sortKey="effort" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 72 }} />
              <SortableTh label={LABELS.vendorFix} sortKey="vendorFix" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 100 }} />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={cveId ? 4 : 5} className="table-empty">
                  No remediations match your filters.
                </td>
              </tr>
            ) : (
              rows.map((s) => (
                <tr key={s.id} onClick={() => navigate(`/cves/${s.cveId}`)}>
                  {!cveId && <td className="mono">{s.cveId}</td>}
                  <td>
                    <div style={{ fontWeight: 500 }}>{s.title}</div>
                    <div className="table-subtext">{s.description}</div>
                  </td>
                  <td>
                    <StatusBadge status={s.status} />
                  </td>
                  <td style={{ textTransform: "capitalize" }}>{s.effort}</td>
                  <td>{s.vendorFixAvailable ? (s.fixedVersion ?? "Yes") : "No"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
