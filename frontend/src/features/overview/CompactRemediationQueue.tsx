import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SolutionStatus } from "@/features/solutions/SolutionStatus";
import { useSolutions } from "@/features/solutions/hooks";
import { useCve } from "@/features/cves/hooks";

export function CompactRemediationQueue({ limit = 5 }: { limit?: number }) {
  const solutions = useSolutions().slice(0, limit);
  const navigate = useNavigate();

  return (
    <Card
      title="Priority queue"
      action={<ViewAllLink to="/solutions" />}
      className="remediation-queue-card"
    >
      <div className="remediation-queue">
        {solutions.length === 0 ? (
          <p className="geo-map__empty">No critical or high findings requiring action.</p>
        ) : (
          solutions.map((item) => (
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
  status: "open" | "triage" | "assigned" | "resolved";
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
        <SolutionStatus status={status} />
      </div>
    </button>
  );
}
