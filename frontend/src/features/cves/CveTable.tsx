import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Cve, Severity, ThreatType } from "@/types";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { THREAT_LABEL } from "@/lib/threats";
import { LABELS } from "@/lib/copy";
import { useCves } from "./hooks";

type Filter = Severity | "all";

interface CveTableProps {
  limit?: number;
  title?: string;
  showFilter?: boolean;
  threatFilter?: ThreatType;
}

export function CveTable({
  limit,
  title = "Security issues",
  showFilter = true,
  threatFilter,
}: CveTableProps) {
  const navigate = useNavigate();
  const cves = useCves();
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(() => {
    let list: Cve[] = cves;
    if (threatFilter) list = list.filter((c) => c.threatType === threatFilter);
    if (filter !== "all") list = list.filter((c) => c.severity === filter);
    return limit ? list.slice(0, limit) : list;
  }, [cves, filter, limit, threatFilter]);

  const displayTitle =
    threatFilter && title === "Security issues"
      ? `${THREAT_LABEL[threatFilter]} issues`
      : title;

  return (
    <Card
      title={displayTitle}
      action={
        showFilter ? (
          <div className="table-filters">
            <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>
              All
            </FilterChip>
            {SEVERITY_ORDER.map((s) => (
              <FilterChip key={s} active={filter === s} onClick={() => setFilter(s)}>
                {SEVERITY_LABEL[s]}
              </FilterChip>
            ))}
          </div>
        ) : (
          <span className="table-meta">{rows.length} shown</span>
        )
      }
    >
      <div style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 132 }}>{LABELS.issueId}</th>
              <th style={{ width: 56 }}>{LABELS.riskScore}</th>
              <th style={{ width: 84 }}>Severity</th>
              <th style={{ width: 92 }}>Ports</th>
              <th style={{ width: 78 }}>Transport</th>
              <th>{LABELS.summary}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} onClick={() => navigate(`/cves/${c.id}`)}>
                <td className="mono">{c.id}</td>
                <td>
                  <CvssScore score={c.cvss} />
                </td>
                <td>
                  <SeverityBadge severity={c.severity} />
                </td>
                <td className="mono">{c.ports.join(", ")}</td>
                <td className="mono">{c.transport}</td>
                <td
                  style={{
                    maxWidth: 0,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    color: "var(--text-secondary)",
                  }}
                >
                  {c.summary}
                </td>
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
