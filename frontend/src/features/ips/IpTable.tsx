import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { CvssScore } from "@/components/CvssScore";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SortableTh } from "@/components/SortableTh";
import { FilterChip, TableToolbar } from "@/components/TableToolbar";
import { useTableState } from "@/hooks/useTableState";
import { LABELS } from "@/lib/copy";
import { formatIpLocation } from "@/lib/geo";
import { formatLastScan } from "@/lib/format";
import { cvssToSeverity, SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import type { IpRecord, Severity } from "@/types";
import { useIps } from "./hooks";

type IpSortKey = "address" | "ipRange" | "hostname" | "serviceCount" | "cveCount" | "maxCvss" | "lastScanAt";
type SeverityFilter = Severity | "all";
type IssueFilter = "all" | "with-issues" | "critical";

interface IpTableProps {
  limit?: number;
  title?: string;
}

function searchIp(ip: IpRecord, query: string): boolean {
  const location = formatIpLocation(ip.city, ip.country);
  const haystack = [ip.address, ip.ipRange, ip.hostname, location]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

function sortIp(ip: IpRecord, key: IpSortKey): string | number {
  switch (key) {
    case "address":
      return ip.address;
    case "ipRange":
      return ip.ipRange ?? "";
    case "hostname":
      return ip.hostname;
    case "serviceCount":
      return ip.serviceCount;
    case "cveCount":
      return ip.cveCount;
    case "maxCvss":
      return ip.maxCvss;
    case "lastScanAt":
      return ip.lastScanAt;
  }
}

export function IpTable({ limit, title = "IP assets" }: IpTableProps) {
  const navigate = useNavigate();
  const ips = useIps();
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [issueFilter, setIssueFilter] = useState<IssueFilter>("all");
  const [countryFilter, setCountryFilter] = useState("all");

  const countries = useMemo(
    () =>
      [...new Set(ips.map((ip) => ip.country).filter(Boolean) as string[])].sort((a, b) =>
        a.localeCompare(b),
      ),
    [ips],
  );

  const source = useMemo(() => {
    let list = ips;
    if (issueFilter === "with-issues") list = list.filter((ip) => ip.cveCount > 0);
    if (issueFilter === "critical") list = list.filter((ip) => ip.criticalCount > 0);
    if (severityFilter !== "all") {
      list = list.filter((ip) => cvssToSeverity(ip.maxCvss) === severityFilter);
    }
    if (countryFilter !== "all") {
      list = list.filter((ip) => ip.country === countryFilter);
    }
    return list;
  }, [ips, countryFilter, issueFilter, severityFilter]);

  const { query, setQuery, sort, toggleSort, rows, total, shown } = useTableState<IpRecord, IpSortKey>({
    items: source,
    defaultSort: { key: "maxCvss", direction: "desc" },
    getSortValue: sortIp,
    search: searchIp,
    limit,
  });

  return (
    <Card title={title}>
      <TableToolbar
        query={query}
        onQueryChange={setQuery}
        shown={shown}
        total={total}
        placeholder="Search IP, hostname, or location…"
        resetVisible={Boolean(query.trim()) || severityFilter !== "all" || issueFilter !== "all" || countryFilter !== "all"}
        onReset={() => {
          setQuery("");
          setSeverityFilter("all");
          setIssueFilter("all");
          setCountryFilter("all");
        }}
        selects={
          countries.length > 1
            ? [
                {
                  label: "Country",
                  value: countryFilter,
                  onChange: setCountryFilter,
                  options: [
                    { value: "all", label: "All countries" },
                    ...countries.map((country) => ({ value: country, label: country })),
                  ],
                },
              ]
            : undefined
        }
        filters={
          <>
            <FilterChip active={issueFilter === "all"} onClick={() => setIssueFilter("all")}>
              All assets
            </FilterChip>
            <FilterChip active={issueFilter === "with-issues"} onClick={() => setIssueFilter("with-issues")}>
              With issues
            </FilterChip>
            <FilterChip active={issueFilter === "critical"} onClick={() => setIssueFilter("critical")}>
              Critical
            </FilterChip>
            {SEVERITY_ORDER.map((s) => (
              <FilterChip
                key={s}
                active={severityFilter === s}
                onClick={() => setSeverityFilter((prev) => (prev === s ? "all" : s))}
              >
                {SEVERITY_LABEL[s]} max
              </FilterChip>
            ))}
          </>
        }
      />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <SortableTh label={LABELS.ipAddress} sortKey="address" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 120 }} />
              <SortableTh label={LABELS.ipRange} sortKey="ipRange" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 128 }} />
              <SortableTh label={LABELS.hostname} sortKey="hostname" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 140 }} />
              <SortableTh label={LABELS.services} sortKey="serviceCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 72 }} />
              <SortableTh label={LABELS.vulns} sortKey="cveCount" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 64 }} />
              <th style={{ width: 88 }}>{LABELS.severity}</th>
              <SortableTh label={LABELS.lastScan} sortKey="lastScanAt" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 120 }} />
              <SortableTh label={LABELS.riskScore} sortKey="maxCvss" activeKey={sort.key} direction={sort.direction} onSort={toggleSort} style={{ width: 80 }} />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={8} className="table-empty">
                  No assets match your filters.
                </td>
              </tr>
            ) : (
              rows.map((ip) => (
                <tr key={ip.id} onClick={() => navigate(`/ips/${encodeURIComponent(ip.id)}`)}>
                  <td className="mono">{ip.address}</td>
                  <td className="mono" style={{ color: "var(--text-secondary)" }}>
                    {ip.ipRange ?? "—"}
                  </td>
                  <td>
                    <span className="mini-table__primary">{ip.hostname}</span>
                    {(ip.city || ip.country) && formatIpLocation(ip.city, ip.country) && (
                      <span className="mini-table__secondary">
                        {formatIpLocation(ip.city, ip.country)}
                      </span>
                    )}
                  </td>
                  <td>{ip.serviceCount}</td>
                  <td>{ip.cveCount}</td>
                  <td>
                    <SeverityBadge severity={cvssToSeverity(ip.maxCvss)} />
                  </td>
                  <td style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                    {formatLastScan(ip.lastScanAt)}
                  </td>
                  <td>
                    <CvssScore score={ip.maxCvss} />
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
