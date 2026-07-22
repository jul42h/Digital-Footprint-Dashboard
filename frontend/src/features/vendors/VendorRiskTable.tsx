import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { SortableTh } from "@/components/SortableTh";
import { FilterChip, TableToolbar } from "@/components/TableToolbar";
import { useTableState } from "@/hooks/useTableState";
import { LABELS } from "@/lib/copy";
import type { VendorRisk } from "@/types";
import { useVendors } from "./hooks";

type VendorSortKey = "name" | "riskScore" | "productCount" | "cveCount" | "criticalCount";
type RiskFilter = "all" | "high" | "urgent";

function searchVendor(vendor: VendorRisk, query: string): boolean {
  return vendor.name.toLowerCase().includes(query);
}

function sortVendor(vendor: VendorRisk, key: VendorSortKey): string | number {
  switch (key) {
    case "name":
      return vendor.name;
    case "riskScore":
      return vendor.riskScore;
    case "productCount":
      return vendor.productCount;
    case "cveCount":
      return vendor.cveCount;
    case "criticalCount":
      return vendor.criticalCount;
  }
}

export function VendorRiskTable({
  title = "Providers ranked by risk",
  limit,
}: {
  title?: string;
  limit?: number;
}) {
  const navigate = useNavigate();
  const vendors = useVendors();
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");

  const source = useMemo(() => {
    if (riskFilter === "high") return vendors.filter((v) => v.riskScore >= 70);
    if (riskFilter === "urgent") return vendors.filter((v) => v.criticalCount > 0);
    return vendors;
  }, [riskFilter, vendors]);

  const { query, setQuery, sort, toggleSort, rows, total, shown } = useTableState<VendorRisk, VendorSortKey>({
    items: source,
    defaultSort: { key: "riskScore", direction: "desc" },
    getSortValue: sortVendor,
    search: searchVendor,
    limit,
  });

  return (
    <Card title={title}>
      <TableToolbar
        query={query}
        onQueryChange={setQuery}
        shown={shown}
        total={total}
        placeholder="Search provider…"
        resetVisible={Boolean(query.trim()) || riskFilter !== "all"}
        onReset={() => {
          setQuery("");
          setRiskFilter("all");
        }}
        filters={
          <>
            <FilterChip active={riskFilter === "all"} onClick={() => setRiskFilter("all")}>
              All providers
            </FilterChip>
            <FilterChip active={riskFilter === "high"} onClick={() => setRiskFilter("high")}>
              High concern (70+)
            </FilterChip>
            <FilterChip active={riskFilter === "urgent"} onClick={() => setRiskFilter("urgent")}>
              Urgent issues
            </FilterChip>
          </>
        }
      />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <SortableTh label={LABELS.provider} sortKey="name" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} />
              <SortableTh label={LABELS.riskLevel} sortKey="riskScore" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 88 }} />
              <SortableTh label={LABELS.software} sortKey="productCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 80 }} />
              <SortableTh label={LABELS.issues} sortKey="cveCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 64 }} />
              <SortableTh label="Urgent" sortKey="criticalCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 72 }} />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="table-empty">
                  No providers match your filters.
                </td>
              </tr>
            ) : (
              rows.map((v) => (
                <tr key={v.id} onClick={() => navigate(`/vendors/${v.id}`)}>
                  <td style={{ fontWeight: 500 }}>{v.name}</td>
                  <td>
                    <RiskScore value={v.riskScore} />
                  </td>
                  <td>{v.productCount}</td>
                  <td>{v.cveCount}</td>
                  <td style={{ color: v.criticalCount > 0 ? "var(--sev-critical)" : undefined }}>
                    {v.criticalCount}
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

function RiskScore({ value }: { value: number }) {
  const color =
    value >= 80 ? "var(--sev-critical)" : value >= 60 ? "var(--sev-high)" : value >= 40 ? "var(--sev-medium)" : "var(--sev-low)";

  return (
    <span className="mono" style={{ color, fontWeight: 500 }}>
      {value}
    </span>
  );
}
