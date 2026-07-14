import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SolutionStatus as SolutionStatusBadge } from "@/features/solutions/SolutionStatus";
import { useSolutions } from "@/features/solutions/hooks";
import { useCve, useCves } from "@/features/cves/hooks";
import { HELP_TEXT } from "@/lib/copy";
import { compareSolutionPriority } from "@/lib/exploitability";
import type { SolutionStatus } from "@/types";

export function CompactRemediationQueue({
  limit = 5,
  compact = false,
}: {
  limit?: number;
  compact?: boolean;
}) {
  const solutions = useSolutions();
  const cves = useCves();
  const navigate = useNavigate();

  const queue = useMemo(() => {
    const cveById = new Map(cves.map((cve) => [cve.id, cve]));
    return [...solutions]
      .sort((a, b) => compareSolutionPriority(cveById.get(a.cveId), cveById.get(b.cveId)))
      .slice(0, limit);
  }, [cves, limit, solutions]);

  return (
    <Card
      title="Fix first"
      action={<ViewAllLink to="/solutions" />}
      className="remediation-queue-card"
    >
      {!compact && (
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.priorityQueue}</p>
      )}
      <div className="remediation-queue">
        {queue.length === 0 ? (
          <p className="geo-map__empty">No critical or high findings requiring action.</p>
        ) : (
          queue.map((item) => (
            <RemediationRow
              key={item.id}
              cveId={item.cveId}
              effort={item.effort}
              status={item.status}
              onOpen={() => navigate(`/cves/${item.cveId}`)}
            />
          ))
        )}
      </div>
    </Card>
  );
}

function RemediationRow({
  cveId,
  effort,
  status,
  onOpen,
}: {
  cveId: string;
  effort: string;
  status: SolutionStatus;
  onOpen: () => void;
}) {
  const cve = useCve(cveId);
  if (!cve) return null;

  return (
    <button type="button" className="remediation-row" onClick={onOpen}>
      <div className="remediation-row__main">
        <SeverityBadge severity={cve.severity} />
        <span className="remediation-row__id mono">{cveId}</span>
        <span className="remediation-row__asset mono">{cve.asset}</span>
      </div>
      <div className="remediation-row__meta">
        <span className={`remediation-row__effort remediation-row__effort--${effort}`}>{effort}</span>
        <SolutionStatusBadge status={status} />
      </div>
    </button>
  );
}
