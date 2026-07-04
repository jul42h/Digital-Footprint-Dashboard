import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { CvssScore } from "@/components/CvssScore";
import { SortableTh } from "@/components/SortableTh";
import { FilterChip, TableToolbar } from "@/components/TableToolbar";
import { useTableState } from "@/hooks/useTableState";
import { LABELS } from "@/lib/copy";
import type { ProductRisk } from "@/types";
import { useProducts, useVendors } from "./hooks";

type ProductSortKey = "vendor" | "name" | "version" | "cveCount" | "maxCvss";
type IssueFilter = "all" | "with-issues" | "high-risk";

interface ProductRow extends ProductRisk {
  vendorName: string;
}

interface ProductRiskTableProps {
  vendorId?: string;
  title?: string;
}

function searchProduct(product: ProductRow, query: string): boolean {
  const haystack = [product.vendorName, product.name, product.version ?? ""].join(" ").toLowerCase();
  return haystack.includes(query);
}

function sortProduct(product: ProductRow, key: ProductSortKey): string | number {
  switch (key) {
    case "vendor":
      return product.vendorName;
    case "name":
      return product.name;
    case "version":
      return product.version ?? "";
    case "cveCount":
      return product.cveCount;
    case "maxCvss":
      return product.maxCvss;
  }
}

export function ProductRiskTable({
  vendorId,
  title = "Software in your environment",
}: ProductRiskTableProps) {
  const navigate = useNavigate();
  const allProducts = useProducts();
  const vendors = useVendors();
  const [issueFilter, setIssueFilter] = useState<IssueFilter>("all");
  const [vendorFilter, setVendorFilter] = useState("all");

  const items = useMemo(() => {
    let list = vendorId ? allProducts.filter((p) => p.vendorId === vendorId) : allProducts;
    if (!vendorId && vendorFilter !== "all") {
      list = list.filter((p) => p.vendorId === vendorFilter);
    }
    if (issueFilter === "with-issues") list = list.filter((p) => p.cveCount > 0);
    if (issueFilter === "high-risk") list = list.filter((p) => p.maxCvss >= 7);
    return list.map((product) => ({
      ...product,
      vendorName: vendors.find((v) => v.id === product.vendorId)?.name ?? "",
    }));
  }, [allProducts, issueFilter, vendorFilter, vendorId, vendors]);

  const { query, setQuery, sort, toggleSort, rows, total, shown } = useTableState<ProductRow, ProductSortKey>({
    items,
    defaultSort: { key: "maxCvss", direction: "desc" },
    getSortValue: sortProduct,
    search: searchProduct,
  });

  return (
    <Card title={title}>
      <TableToolbar
        query={query}
        onQueryChange={setQuery}
        shown={shown}
        total={total}
        placeholder="Search software, version, or provider…"
        selects={
          !vendorId && vendors.length > 1
            ? [
                {
                  label: "Provider",
                  value: vendorFilter,
                  onChange: setVendorFilter,
                  options: [
                    { value: "all", label: "All providers" },
                    ...vendors.map((vendor) => ({ value: vendor.id, label: vendor.name })),
                  ],
                },
              ]
            : undefined
        }
        filters={
          <>
            <FilterChip active={issueFilter === "all"} onClick={() => setIssueFilter("all")}>
              All software
            </FilterChip>
            <FilterChip active={issueFilter === "with-issues"} onClick={() => setIssueFilter("with-issues")}>
              With issues
            </FilterChip>
            <FilterChip active={issueFilter === "high-risk"} onClick={() => setIssueFilter("high-risk")}>
              High risk (7+)
            </FilterChip>
          </>
        }
      />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              {!vendorId && (
                <SortableTh label={LABELS.provider} sortKey="vendor" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 140 }} />
              )}
              <SortableTh label={LABELS.software} sortKey="name" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} />
              <SortableTh label={LABELS.version} sortKey="version" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 100 }} />
              <SortableTh label={LABELS.issues} sortKey="cveCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 64 }} />
              <SortableTh label={LABELS.riskScore} sortKey="maxCvss" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 80 }} />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={vendorId ? 4 : 5} className="table-empty">
                  No software matches your filters.
                </td>
              </tr>
            ) : (
              rows.map((p) => (
                <tr key={p.id} onClick={() => navigate(`/vendors/${p.vendorId}`)}>
                  {!vendorId && <td>{p.vendorName || "—"}</td>}
                  <td style={{ fontWeight: 500 }}>{p.name}</td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {p.version ?? "—"}
                  </td>
                  <td>{p.cveCount}</td>
                  <td>
                    <CvssScore score={p.maxCvss} />
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
