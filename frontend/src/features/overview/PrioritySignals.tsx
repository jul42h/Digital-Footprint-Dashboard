import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { pickKevCveIds, pickPriorityCveIds } from "@/features/ask-ai/cveSelection";
import { MAX_CVE_IDS_PER_REQUEST } from "@/features/ask-ai/types";
import { useCves } from "@/features/cves/hooks";
import { HELP_TEXT } from "@/lib/copy";
import { SEVERITY_COLOR } from "@/lib/severity";
import { useDashboard } from "@/context/DashboardContext";
import { useDashboardSummary } from "./useDashboardSummary";

/** Compact actionable signals beside severity. */
export function PrioritySignals() {
  const { data } = useDashboard();
  const { critical, exploited, pendingRemediations } = useDashboardSummary();
  const cves = useCves();
  const { openWithCves } = useAskAiUi();

  const epssHigh = useMemo(
    () => cves.filter((c) => c.epss != null && c.epss >= 0.5).length,
    [cves],
  );

  const kevIds = useMemo(
    () => pickKevCveIds(cves, MAX_CVE_IDS_PER_REQUEST),
    [cves],
  );
  const priorityIds = useMemo(
    () => pickPriorityCveIds(cves, MAX_CVE_IDS_PER_REQUEST),
    [cves],
  );

  const rows = [
    {
      key: "kev",
      label: "Known exploited",
      value: data.stats.kevFindings || exploited,
      tone: (data.stats.kevFindings || exploited) > 0 ? SEVERITY_COLOR.high : undefined,
      action: () => {
        if (kevIds.length) openWithCves(kevIds);
      },
      actionLabel: "Analyze",
      disabled: kevIds.length === 0,
    },
    {
      key: "epss",
      label: "High EPSS (≥0.5)",
      value: epssHigh,
      tone: epssHigh > 0 ? SEVERITY_COLOR.medium : undefined,
      action: () => openWithCves(priorityIds),
      actionLabel: "Analyze",
      disabled: priorityIds.length === 0,
    },
    {
      key: "critical",
      label: "Critical issues",
      value: critical,
      tone: critical > 0 ? SEVERITY_COLOR.critical : undefined,
      to: "/cves",
    },
    {
      key: "fixes",
      label: "Pending remediations",
      value: pendingRemediations,
      tone: pendingRemediations > 0 ? SEVERITY_COLOR.high : undefined,
      to: "/solutions",
    },
  ] as const;

  return (
    <section className="home-panel priority-signals" aria-labelledby="home-signals-label">
      <h2 id="home-signals-label" className="home-panel__title">
        Priority signals
      </h2>
      <p className="home-panel__hint">{HELP_TEXT.prioritySignals}</p>

      <ul className="priority-signals__list">
        {rows.map((row) => (
          <li key={row.key} className="priority-signals__row">
            <div className="priority-signals__main">
              <span
                className="priority-signals__value"
                style={row.tone ? { color: row.tone } : undefined}
              >
                {row.value}
              </span>
              <span className="priority-signals__label">{row.label}</span>
            </div>
            {"to" in row && row.to ? (
              <Link to={row.to} className="priority-signals__action">
                View
              </Link>
            ) : (
              <button
                type="button"
                className="priority-signals__action"
                disabled={"disabled" in row ? row.disabled : false}
                onClick={"action" in row ? row.action : undefined}
              >
                {"actionLabel" in row ? row.actionLabel : "Open"}
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
