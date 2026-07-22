import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Cve, Severity, ThreatType, Transport } from "@/types";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { SortableTh } from "@/components/SortableTh";
import { FilterChip, TableToolbar } from "@/components/TableToolbar";
import { useTableState } from "@/hooks/useTableState";
import { HIGH_EPSS } from "@/lib/exploitability";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { THREAT_LABEL, THREAT_ORDER } from "@/lib/threats";
import { LABELS } from "@/lib/copy";
import { useCves } from "./hooks";

type Filter = Severity | "all";
type CveSortKey = "id" | "cvss" | "severity" | "ports" | "transport" | "summary" | "epss";
type TransportFilter = Transport | "all";
type KevFilter = "all" | "exploited" | "high-epss";

interface CveTableProps {
  limit?: number;
  title?: string;
  showFilter?: boolean;
  threatFilter?: ThreatType;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function searchCve(cve: Cve, query: string): boolean {
  const haystack = [cve.id, cve.summary, cve.asset, cve.transport, cve.ports.join(" ")].join(" ").toLowerCase();
  return haystack.includes(query);
}

function sortCve(cve: Cve, key: CveSortKey): string | number {
  switch (key) {
    case "id":
      return cve.id;
    case "cvss":
      return cve.cvss;
    case "severity":
      return SEVERITY_RANK[cve.severity];
    case "ports":
      return cve.ports[0] ?? 0;
    case "transport":
      return cve.transport;
    case "summary":
      return cve.summary;
    case "epss":
      return cve.epss ?? -1;
  }
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
  const [threatType, setThreatType] = useState<ThreatType | "all">(threatFilter ?? "all");
  const [transportFilter, setTransportFilter] = useState<TransportFilter>("all");
  const [kevFilter, setKevFilter] = useState<KevFilter>("all");

  const source = useMemo(() => {
    let list = cves;
    const activeThreat = threatFilter ?? (threatType === "all" ? null : threatType);
    if (activeThreat) list = list.filter((c) => c.threatType === activeThreat);
    if (filter !== "all") list = list.filter((c) => c.severity === filter);
    if (transportFilter !== "all") list = list.filter((c) => c.transport === transportFilter);
    if (kevFilter === "exploited") list = list.filter((c) => c.exploitKnown);
    if (kevFilter === "high-epss") list = list.filter((c) => (c.epss ?? 0) >= HIGH_EPSS);
    return list;
  }, [cves, filter, kevFilter, threatFilter, threatType, transportFilter]);

  const { query, setQuery, sort, toggleSort, rows, total, shown } = useTableState<Cve, CveSortKey>({
    items: source,
    defaultSort: { key: "cvss", direction: "desc" },
    getSortValue: sortCve,
    search: searchCve,
    limit,
  });

  const displayTitle =
    threatFilter && title === "Security issues"
      ? `${THREAT_LABEL[threatFilter]} issues`
      : title;

  return (
    <Card title={displayTitle}>
      <TableToolbar
        query={query}
        onQueryChange={setQuery}
        shown={shown}
        total={total}
        placeholder="Search CVE, summary, or asset…"
        resetVisible={Boolean(query.trim()) || filter !== "all" || (!threatFilter && threatType !== "all") || transportFilter !== "all" || kevFilter !== "all"}
        onReset={() => {
          setQuery("");
          setFilter("all");
          setThreatType(threatFilter ?? "all");
          setTransportFilter("all");
          setKevFilter("all");
        }}
        selects={
          showFilter && !threatFilter
            ? [
                {
                  label: "Threat type",
                  value: threatType,
                  onChange: (value) => setThreatType(value as ThreatType | "all"),
                  options: [
                    { value: "all", label: "All threat types" },
                    ...THREAT_ORDER.map((type) => ({ value: type, label: THREAT_LABEL[type] })),
                  ],
                },
              ]
            : undefined
        }
        filters={
          showFilter ? (
            <>
              <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>
                All severities
              </FilterChip>
              {SEVERITY_ORDER.map((s) => (
                <FilterChip key={s} active={filter === s} onClick={() => setFilter(s)}>
                  {SEVERITY_LABEL[s]}
                </FilterChip>
              ))}
              <FilterChip active={transportFilter === "TCP"} onClick={() => setTransportFilter((v) => (v === "TCP" ? "all" : "TCP"))}>
                TCP
              </FilterChip>
              <FilterChip active={transportFilter === "UDP"} onClick={() => setTransportFilter((v) => (v === "UDP" ? "all" : "UDP"))}>
                UDP
              </FilterChip>
              <FilterChip active={kevFilter === "exploited"} onClick={() => setKevFilter((v) => (v === "exploited" ? "all" : "exploited"))}>
                Known exploited
              </FilterChip>
              <FilterChip active={kevFilter === "high-epss"} onClick={() => setKevFilter((v) => (v === "high-epss" ? "all" : "high-epss"))}>
                High EPSS
              </FilterChip>
            </>
          ) : undefined
        }
      />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <SortableTh label={LABELS.issueId} sortKey="id" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 132 }} />
              <SortableTh label={LABELS.riskScore} sortKey="cvss" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 56 }} />
              <SortableTh label="Severity" sortKey="severity" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 84 }} />
              <SortableTh label="Ports" sortKey="ports" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 92 }} />
              <SortableTh label="Transport" sortKey="transport" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 78 }} />
              <SortableTh label="EPSS" sortKey="epss" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 64 }} />
              <SortableTh label={LABELS.summary} sortKey="summary" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="table-empty">
                  No issues match your filters.
                </td>
              </tr>
            ) : (
              rows.map((c) => (
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
                  <td className="mono" style={{ color: "var(--text-secondary)" }}>
                    {c.epss != null ? `${(c.epss * 100).toFixed(1)}%` : "—"}
                  </td>
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
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
