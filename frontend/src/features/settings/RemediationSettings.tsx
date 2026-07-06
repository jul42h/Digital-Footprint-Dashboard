import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card } from "@/components/Card";
import { FilterChip } from "@/components/TableToolbar";
import { useRemediation } from "@/context/RemediationContext";
import { DEFAULT_STATUS_LABELS, SOLUTION_STATUS_ORDER } from "@/lib/remediationConfig";
import type { SolutionStatus } from "@/types";

export function RemediationSettings() {
  const {
    statusLabels,
    pendingStatuses,
    getStatusLabel,
    setStatusLabel,
    resetStatusLabels,
    togglePendingStatus,
    resetPendingStatuses,
  } = useRemediation();
  const [drafts, setDrafts] = useState<Record<SolutionStatus, string>>(statusLabels);

  useEffect(() => {
    setDrafts(statusLabels);
  }, [statusLabels]);

  return (
    <Card title="Remediation statuses">
      <p className="card-footnote">
        <strong>Change an item&apos;s status:</strong> open <em>Remediations</em> or the home{" "}
        <em>Priority queue</em>, then use the status dropdown on any row (not the CVE link).
        Changes save automatically in this browser.
      </p>

      <h3 className="settings-section-title">Status labels</h3>
      <p className="card-footnote card-footnote--tight">
        Rename how each status appears across the dashboard. See the{" "}
        <Link to="/guide#remediation-statuses">remediation guide</Link> for what each status means.
      </p>

      {SOLUTION_STATUS_ORDER.map((status) => (
        <div className="detail-row" key={status}>
          <span className="detail-row__label mono">{status}</span>
          <span className="detail-row__value">
            <input
              className="status-label-input"
              type="text"
              value={drafts[status]}
              onChange={(e) => setDrafts((prev) => ({ ...prev, [status]: e.target.value }))}
              onBlur={() => setStatusLabel(status, drafts[status])}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.currentTarget.blur();
                }
              }}
            />
          </span>
        </div>
      ))}

      <h3 className="settings-section-title">Pending statuses</h3>
      <p className="card-footnote card-footnote--tight">
        Selected statuses count toward the home &quot;Remediations&quot; metric and the pending
        count on the fixes chart.
      </p>
      <div className="table-toolbar__filters settings-status-filters">
        {SOLUTION_STATUS_ORDER.map((status) => (
          <FilterChip
            key={status}
            active={pendingStatuses.includes(status)}
            onClick={() => togglePendingStatus(status)}
          >
            {getStatusLabel(status)}
          </FilterChip>
        ))}
      </div>

      <div className="settings-actions">
        <button
          type="button"
          className="btn btn--compact"
          onClick={() => {
            resetStatusLabels();
            resetPendingStatuses();
            setDrafts({ ...DEFAULT_STATUS_LABELS });
          }}
        >
          Reset all
        </button>
      </div>
    </Card>
  );
}
