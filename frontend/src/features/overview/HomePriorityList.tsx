import { useNavigate } from "react-router-dom";
import { Card } from "@/components/Card";
import { ViewAllLink } from "@/components/ViewAllLink";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useCves } from "@/features/cves/hooks";

export function HomePriorityList({ limit = 5 }: { limit?: number }) {
  const navigate = useNavigate();
  const issues = useCves().slice(0, limit);

  return (
    <Card
      title="Top CVEs"
      action={<ViewAllLink to="/cves" />}
    >
      <ul className="priority-list">
        {issues.map((issue) => (
          <li key={issue.id}>
            <button
              type="button"
              className="priority-list__item"
              onClick={() => navigate(`/cves/${issue.id}`)}
            >
              <div className="priority-list__main">
                <SeverityBadge severity={issue.severity} />
                <div className="priority-list__text">
                  <span className="priority-list__summary">{issue.summary}</span>
                  <span className="priority-list__id mono">{issue.id}</span>
                </div>
              </div>
              <span className="priority-list__meta">{issue.asset}</span>
            </button>
          </li>
        ))}
      </ul>
    </Card>
  );
}
