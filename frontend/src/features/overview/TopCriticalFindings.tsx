import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { SeverityBadge } from "@/components/SeverityBadge";
import { DEFAULT_PRIORITY_COUNT, pickPriorityCves } from "@/features/ask-ai/cveSelection";
import { useCves } from "@/features/cves/hooks";

function exploitSignal(exploitKnown: boolean | undefined, epss: number | undefined): string {
  if (exploitKnown) return "Known exploited";
  if (epss != null && epss > 0) return `EPSS ${(epss * 100).toFixed(0)}%`;
  return "—";
}

/** The concrete findings the AI brief is about — same ranking, shown as rows. */
export function TopCriticalFindings() {
  const navigate = useNavigate();
  const cves = useCves();
  const top = useMemo(() => pickPriorityCves(cves, DEFAULT_PRIORITY_COUNT), [cves]);

  if (!top.length) {
    return (
      <div className="home-panel">
        <p className="empty-note">No findings loaded yet.</p>
      </div>
    );
  }

  return (
    <div className="home-panel">
      <table className="mini-table">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Asset</th>
            <th>Severity</th>
            <th>Signal</th>
          </tr>
        </thead>
        <tbody>
          {top.map((cve) => (
            <tr key={cve.id} onClick={() => navigate(`/cves/${cve.id}`)}>
              <td>
                <span className="mini-table__primary mono">{cve.id}</span>
              </td>
              <td>
                <span className="mini-table__secondary mono">{cve.asset}</span>
              </td>
              <td>
                <SeverityBadge severity={cve.severity} />
              </td>
              <td>
                <span className="mini-table__secondary mono">
                  {exploitSignal(cve.exploitKnown, cve.epss)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
