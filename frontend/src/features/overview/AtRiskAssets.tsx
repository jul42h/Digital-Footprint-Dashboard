import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { FilterChip } from "@/components/TableToolbar";
import { ViewAllLink } from "@/components/ViewAllLink";
import { cvssToSeverity, SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { HELP_TEXT } from "@/lib/copy";
import { formatIpLocation } from "@/lib/geo";
import type { Severity } from "@/types";
import { useIps } from "@/features/ips/hooks";

type SeverityFilter = Severity | "all";

export function AtRiskAssets({ limit = 5 }: { limit?: number }) {
  const navigate = useNavigate();
  const ips = useIps();
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");

  const assets = useMemo(() => {
    let list = ips.filter((ip) => ip.cveCount > 0);
    if (severityFilter !== "all") {
      list = list.filter((ip) => cvssToSeverity(ip.maxCvss) === severityFilter);
    }
    return list.sort((a, b) => b.maxCvss - a.maxCvss).slice(0, limit);
  }, [ips, limit, severityFilter]);

  return (
    <Card
      title="Highest-risk assets"
      action={<ViewAllLink to="/ips" />}
    >
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.atRiskAssets}</p>
      <div className="table-toolbar__filters" style={{ marginBottom: 10 }}>
        <FilterChip active={severityFilter === "all"} onClick={() => setSeverityFilter("all")}>
          All
        </FilterChip>
        {SEVERITY_ORDER.map((s) => (
          <FilterChip key={s} active={severityFilter === s} onClick={() => setSeverityFilter(s)}>
            {SEVERITY_LABEL[s]}
          </FilterChip>
        ))}
      </div>
      <table className="mini-table">
        <thead>
          <tr>
            <th>Asset</th>
            <th>Vulns</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {assets.length === 0 ? (
            <tr>
              <td colSpan={3} className="table-empty">
                No assets match this filter.
              </td>
            </tr>
          ) : (
            assets.map((asset) => (
              <tr
                key={asset.address}
                onClick={() => navigate(`/ips/${encodeURIComponent(asset.address)}`)}
              >
                <td>
                  <span className="mini-table__primary">{asset.hostname}</span>
                  <span className="mini-table__secondary mono">{asset.address}</span>
                  {formatIpLocation(asset.city, asset.country) && (
                    <span className="mini-table__secondary">
                      {formatIpLocation(asset.city, asset.country)}
                    </span>
                  )}
                </td>
                <td>{asset.cveCount}</td>
                <td>
                  <SeverityBadge severity={cvssToSeverity(asset.maxCvss)} />
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </Card>
  );
}
