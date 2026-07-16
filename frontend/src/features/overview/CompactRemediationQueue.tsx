import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SolutionStatus as SolutionStatusBadge } from "@/features/solutions/SolutionStatus";
import { useSolutions } from "@/features/solutions/hooks";
import { useCves } from "@/features/cves/hooks";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { compareSolutionPriority } from "@/lib/exploitability";
import type { Cve, SolutionStatus } from "@/types";

export function CompactRemediationQueue({
  limit = 5,
  compact = false,
  hideTitle = false,
}: {
  limit?: number;
  compact?: boolean;
  hideTitle?: boolean;
}) {
  const solutions = useSolutions();
  const cves = useCves();
  const navigate = useNavigate();

  const queue = useMemo(() => {
    const cveById = new Map(cves.map((cve) => [cve.id, cve]));
    return [...solutions]
      .sort((a, b) => compareSolutionPriority(cveById.get(a.cveId), cveById.get(b.cveId)))
      .slice(0, limit)
      .map((item) => ({ item, cve: cveById.get(item.cveId) ?? null }));
  }, [cves, limit, solutions]);

  const body = (
    <div className="remediation-queue">
      {queue.length === 0 ? (
        <p className="empty-note">No pending remediations for critical or high findings.</p>
      ) : (
        queue.map(({ item, cve }) =>
          cve ? (
            <RemediationRow
              key={item.id}
              cve={cve}
              effort={item.effort}
              status={item.status}
              onOpen={() => navigate(`/cves/${item.cveId}`)}
            />
          ) : null,
        )
      )}
    </div>
  );

  if (hideTitle) {
    return <div className="home-panel remediation-queue-card">{body}</div>;
  }

  return (
    <Card
      title={NAV_LABELS.fixes}
      action={<ViewAllLink to="/solutions" />}
      className="remediation-queue-card"
    >
      {!compact && (
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.fixFirst}</p>
      )}
      {body}
    </Card>
  );
}

function RemediationRow({
  cve,
  effort,
  status,
  onOpen,
}: {
  cve: Cve;
  effort: string;
  status: SolutionStatus;
  onOpen: () => void;
}) {
  return (
    <button type="button" className="remediation-row" onClick={onOpen}>
      <div className="remediation-row__main">
        <SeverityBadge severity={cve.severity} />
        <span className="remediation-row__id mono">{cve.id}</span>
        <span className="remediation-row__asset mono">{cve.asset}</span>
      </div>
      <div className="remediation-row__meta">
        <span className={`remediation-row__effort remediation-row__effort--${effort}`}>{effort}</span>
        <SolutionStatusBadge status={status} />
      </div>
    </button>
  );
}
