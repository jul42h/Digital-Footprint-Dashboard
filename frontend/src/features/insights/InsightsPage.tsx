import { useMemo } from "react";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { useDashboard } from "@/context/DashboardContext";
import { toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { MAX_FINDINGS_PER_REQUEST } from "@/features/ask-ai/types";
import type { AnalysisFinding } from "@/features/ask-ai/types";
import { AiBriefMarkdown } from "@/features/overview/AiBriefMarkdown";
import { AiBriefStrip } from "@/features/overview/AiBriefStrip";
import { SEVERITY_COLOR } from "@/lib/severity";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useAiSection, type SectionIntent } from "./useAiSection";

function RefreshButton({ onClick, loading, disabled }: { onClick: () => void; loading: boolean; disabled?: boolean }) {
  return (
    <button
      type="button"
      className="ai-brief__ask ai-brief__ask--secondary"
      onClick={onClick}
      disabled={loading || disabled}
    >
      {loading ? "…" : "Refresh"}
    </button>
  );
}

function SectionBody({
  findings,
  loading,
  hasContent,
  content,
  error,
}: {
  findings: AnalysisFinding[];
  loading: boolean;
  hasContent: boolean;
  content: string | null | undefined;
  error: string | null;
}) {
  if (!findings.length) return <p className="ai-brief__summary">No findings loaded yet.</p>;
  if (loading && !hasContent) {
    return (
      <p className="ai-brief__summary ai-brief__summary--skeleton" aria-live="polite">
        Generating…
      </p>
    );
  }
  if (hasContent) return <AiBriefMarkdown content={content ?? ""} />;
  return <p className="ai-brief__summary">{error || "Analysis unavailable — try Refresh."}</p>;
}

/** Generic whole-system AI card: title, refresh action, and the section body. */
function AiInsightSection({
  title,
  hint,
  intent,
  findings,
}: {
  title: string;
  hint: string;
  intent: SectionIntent;
  findings: AnalysisFinding[];
}) {
  const { data, loading, error, refresh } = useAiSection(intent, findings);
  const hasContent = Boolean(data?.ai_summary);

  return (
    <Card
      title={title}
      action={<RefreshButton onClick={refresh} loading={loading} disabled={!findings.length} />}
      className="insights-card"
    >
      <p className="card-footnote card-footnote--tight">{hint}</p>
      <div className="insights-card__layout">
        <div className="insights-card__body">
          <SectionBody
            findings={findings}
            loading={loading}
            hasContent={hasContent}
            content={data?.ai_summary}
            error={error}
          />
        </div>
      </div>
    </Card>
  );
}

function driverLabel(driver: string): string {
  return driver.charAt(0).toUpperCase() + driver.slice(1);
}

const RATING_COLOR: Record<string, string> = {
  critical: SEVERITY_COLOR.critical,
  high: SEVERITY_COLOR.high,
  elevated: SEVERITY_COLOR.medium,
  moderate: SEVERITY_COLOR.low,
  low: SEVERITY_COLOR.low,
};

/** The Risk Score card: the pipeline-computed score/rating/drivers, plus the
 * model's rationale for that exact number (it never computes its own). */
function RiskScoreSection({ findings }: { findings: AnalysisFinding[] }) {
  const { data, loading, error, refresh } = useAiSection("risk_score", findings);
  const risk = data?.risk_score;
  const hasContent = Boolean(data?.ai_summary && risk);
  const tone = risk ? RATING_COLOR[risk.rating] ?? SEVERITY_COLOR.medium : undefined;

  return (
    <Card
      title="Risk score"
      action={<RefreshButton onClick={refresh} loading={loading} disabled={!findings.length} />}
      className="insights-card"
    >
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.riskScoreSection}</p>
      <div className="insights-card__layout">
        {risk && (
          <div className="risk-score-badge">
            <span className="risk-score-badge__value" style={{ color: tone }}>
              {risk.score}
            </span>
            <span className="risk-score-badge__rating" style={{ color: tone }}>
              {risk.rating}
            </span>
            <span className="risk-score-badge__confidence">{risk.confidence} confidence</span>
          </div>
        )}
        <div className="insights-card__body">
          <SectionBody
            findings={findings}
            loading={loading}
            hasContent={hasContent}
            content={data?.ai_summary}
            error={error}
          />
          {hasContent && risk && risk.drivers.length > 0 && (
            <ul className="risk-score-drivers">
              {risk.drivers.map((driver) => (
                <li key={driver.driver}>
                  <strong>{driverLabel(driver.driver)}</strong> — {driver.evidence}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  );
}

/** AI Risk Intelligence: whole-system summary, insights, explainable risk score,
 * threat intelligence, top critical findings, and highest-risk assets. */
export function InsightsPage() {
  const { data: dashboard } = useDashboard();

  const findings = useMemo(
    () => toAnalysisFindingsFromData(dashboard, { limit: MAX_FINDINGS_PER_REQUEST }),
    [dashboard],
  );

  return (
    <div className="page">
      <PageHeader title={NAV_LABELS.insights} subtitle={HELP_TEXT.insightsPage} />

      <Card title="AI summary" className="insights-card">
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.aiSummarySection}</p>
        <AiBriefStrip variant="business" />
      </Card>

      <AiInsightSection
        title="AI insights"
        hint={HELP_TEXT.aiInsightsSection}
        intent="insights"
        findings={findings}
      />

      <RiskScoreSection findings={findings} />

      <AiInsightSection
        title="Threat intelligence"
        hint={HELP_TEXT.threatIntelSection}
        intent="threat_intel"
        findings={findings}
      />

      <AiInsightSection
        title="Top critical findings"
        hint={HELP_TEXT.criticalFindingsSection}
        intent="critical_findings"
        findings={findings}
      />

      <AiInsightSection
        title="Highest-risk assets"
        hint={HELP_TEXT.riskAssetsSection}
        intent="risk_assets"
        findings={findings}
      />
    </div>
  );
}
