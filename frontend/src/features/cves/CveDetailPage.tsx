import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card } from "@/components/Card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { CvssScore } from "@/components/CvssScore";
import { SolutionTable } from "@/features/solutions/SolutionTable";
import { analyzeCves, peekCachedAnalysis } from "@/features/ask-ai/askAiApi";
import { toAnalysisFindings, toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { sanitizeAiText } from "@/features/ask-ai/sanitizeAiText";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { useDashboard } from "@/context/DashboardContext";
import { LABELS, NAV_LABELS } from "@/lib/copy";
import { useCve } from "./hooks";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-row">
      <span className="detail-row__label">{label}</span>
      <span className="detail-row__value">{children}</span>
    </div>
  );
}

export function CveDetailPage() {
  const { id = "" } = useParams();
  const cve = useCve(id);
  const { data: dashboard } = useDashboard();
  const { openWithCves } = useAskAiUi();
  const [summary, setSummary] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Show session-cached detail immediately when navigating to a CVE.
  useEffect(() => {
    if (!cve) {
      setSummary(null);
      return;
    }
    const cached = peekCachedAnalysis([cve.id], "insights");
    setSummary(sanitizeAiText(cached?.ai_summary) || null);
    setError(null);
  }, [cve?.id]);

  const runAnalysis = async (bypassCache = false) => {
    if (!cve || loading) return;
    setLoading(true);
    setError(null);
    try {
      const fromRecords = toAnalysisFindingsFromData(dashboard, {
        onlyCveIds: [cve.id],
        preferCveIds: [cve.id],
      });
      const result = await analyzeCves([cve.id], {
        intent: "insights",
        findings: fromRecords.length ? fromRecords : toAnalysisFindings([cve]),
        bypassCache,
      });
      setSummary(sanitizeAiText(result.ai_summary) || "No summary returned.");
    } catch (err) {
      setSummary(null);
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page page--narrow">
      <Link to="/cves" className="back-link">
        ← {NAV_LABELS.issues}
      </Link>

      {!cve ? (
        <Card>We could not find that issue.</Card>
      ) : (
        <Card
          title={cve.id}
          action={cve.exploitKnown ? <SeverityBadge severity="critical" /> : undefined}
        >
          <p className="issue-summary">{cve.summary}</p>

          <Row label="Severity">
            <SeverityBadge severity={cve.severity} />
          </Row>
          <Row label={LABELS.riskScore}>
            <CvssScore score={cve.cvss} />
            {cve.cvssVersion && (
              <span style={{ marginLeft: 8, color: "var(--text-secondary)", fontSize: 13 }}>
                CVSS v{cve.cvssVersion}
              </span>
            )}
          </Row>
          <Row label={LABELS.system}>
            <span className="mono">{cve.asset}</span>
          </Row>
          <Row label={LABELS.networkPorts}>
            <span className="mono">{cve.ports.join(", ")} ({cve.transport})</span>
          </Row>
          <Row label={LABELS.activelyTargeted}>
            {cve.exploitKnown ? "Yes — known exploited vulnerability (KEV)" : "No known active exploitation"}
          </Row>
          {cve.epss != null && (
            <Row label="EPSS score">
              {(cve.epss * 100).toFixed(2)}% probability of exploitation in 30 days
            </Row>
          )}
          {cve.verified && (
            <Row label="Verified exposure">
              Yes — confirmed by Shodan scan metadata
            </Row>
          )}
          {cve.affectedAssets && cve.affectedAssets.length > 1 && (
            <Row label="Affected assets">
              <span className="mono">{cve.affectedAssets.join(", ")}</span>
            </Row>
          )}
          <Row label={LABELS.published}>
            {new Date(cve.publishedAt).toLocaleDateString(undefined, {
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          </Row>
        </Card>
      )}

      {cve && (
        <Card
          title="Analyst notes"
          action={
            <div className="cve-ai-actions">
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => openWithCves([cve.id])}
                disabled={loading}
              >
                Open panel
              </button>
              <button
                type="button"
                className="btn btn--primary"
                onClick={() => void runAnalysis(Boolean(summary))}
                disabled={loading}
              >
                {loading ? "Analyzing…" : summary ? "Re-analyze" : "Analyze"}
              </button>
            </div>
          }
        >
          {loading && <p className="cve-ai-status">Generating a detailed write-up for this CVE…</p>}
          {!loading && error && <p className="ask-ai-error">{error}</p>}
          {!loading && summary && (
            <div className="cve-ai-summary">
              {summary.split("\n").map((line, idx) => (
                <p key={idx}>{line.trim() || "\u00A0"}</p>
              ))}
            </div>
          )}
          {!loading && !summary && !error && (
            <p className="cve-ai-status">
              Run analysis for an analyst-level view of {cve.id}: why it matters here,
              exploitability, and what to do next.
            </p>
          )}
        </Card>
      )}

      {cve && (
        <SolutionTable
          cveId={cve.id}
          title="Remediations"
          showFilter={false}
        />
      )}
    </div>
  );
}
