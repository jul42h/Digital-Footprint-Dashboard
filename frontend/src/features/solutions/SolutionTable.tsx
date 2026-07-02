import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { SolutionStatus } from "@/types";
import { Card } from "@/components/Card";
import { LABELS } from "@/lib/copy";
import { SolutionStatus as StatusBadge } from "./SolutionStatus";
import { useSolutions } from "./hooks";

type Filter = SolutionStatus | "all";

const STATUS_ORDER: SolutionStatus[] = ["open", "triage", "assigned", "resolved"];

const STATUS_LABEL: Record<SolutionStatus, string> = {
  open: "Not started",
  triage: "Under review",
  assigned: "In progress",
  resolved: "Done",
};

interface SolutionTableProps {
  cveId?: string;
  limit?: number;
  title?: string;
  showFilter?: boolean;
  action?: React.ReactNode;
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
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(() => {
    let list = cveId ? all.filter((s) => s.cveId === cveId) : all;
    if (filter !== "all") list = list.filter((s) => s.status === filter);
    return limit ? list.slice(0, limit) : list;
  }, [all, cveId, filter, limit]);

  return (
    <Card
      title={title}
      action={
        action ??
        (showFilter ? (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>
              All
            </FilterChip>
            {STATUS_ORDER.map((s) => (
              <FilterChip key={s} active={filter === s} onClick={() => setFilter(s)}>
                {STATUS_LABEL[s]}
              </FilterChip>
            ))}
          </div>
        ) : (
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            {rows.length} option{rows.length !== 1 ? "s" : ""}
          </span>
        ))
      }
    >
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              {!cveId && <th style={{ width: 132 }}>{LABELS.issueId}</th>}
              <th>What to do</th>
              <th style={{ width: 100 }}>{LABELS.status}</th>
              <th style={{ width: 72 }}>{LABELS.effort}</th>
              <th style={{ width: 100 }}>{LABELS.vendorFix}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
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
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      className="btn"
      onClick={onClick}
      style={{
        padding: "4px 10px",
        fontSize: 12,
        color: active ? "var(--text)" : "var(--text-secondary)",
        background: active ? "var(--surface-2)" : "transparent",
      }}
    >
      {children}
    </button>
  );
}
