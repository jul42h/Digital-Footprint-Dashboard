import { useMemo } from "react";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { useDashboard } from "@/context/DashboardContext";
import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { MAX_FINDINGS_PER_REQUEST } from "@/features/ask-ai/types";
import type { AnalysisFinding, CveAnalysisResponse } from "@/features/ask-ai/types";
import { AiBriefMarkdown } from "@/features/overview/AiBriefMarkdown";
import { SEVERITY_COLOR } from "@/lib/severity";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { useAiSection, type SectionIntent } from "./useAiSection";

function AnalysisButton({
  onClick,
  loading,
  hasContent,
  disabled,
}: {
  onClick: () => void;
  loading: boolean;
  hasContent: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className="ai-brief__ask ai-brief__ask--secondary"
      onClick={onClick}
      disabled={loading || disabled}
    >
      {loading ? "Generating…" : hasContent ? "Refresh" : "Generate"}
    </button>
  );
}

function freshnessText(data: CveAnalysisResponse | null, updatedAt: number | null): string | null {
  const generated = data?.generated_at ? Date.parse(data.generated_at) : Number.NaN;
  const timestamp = Number.isFinite(generated) ? generated : updatedAt;
  if (!timestamp) return null;

  const minutes = Math.max(0, Math.round((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return "Generated just now";
  if (minutes < 60) return `Generated ${minutes}m ago`;
  return `Generated ${Math.round(minutes / 60)}h ago`;
}

function SectionBody({
  findings,
  loading,
  requested,
  hasContent,
  content,
  error,
}: {
  findings: AnalysisFinding[];
  loading: boolean;
  requested: boolean;
  hasContent: boolean;
  content: string | null | undefined;
  error: string | null;
}) {
  if (!findings.length) return <p className="ai-brief__summary">No findings loaded yet.</p>;
  if (loading && !hasContent) {
    return (
      <p className="ai-brief__summary ai-brief__summary--skeleton" aria-live="polite">
        Generating analysis…
      </p>
    );
  }
  if (hasContent) return <AiBriefMarkdown content={content ?? ""} />;
  if (!requested) {
    return (
      <p className="ai-section-idle">
        Generate this deeper analysis when you need it. This avoids running every AI view at once.
      </p>
    );
  }
  return <p className="ai-brief__summary">{error || "Analysis unavailable — try again."}</p>;
}

function AiInsightSection({
  title,
  hint,
  intent,
  findings,
  className,
}: {
  title: string;
  hint: string;
  intent: SectionIntent;
  findings: AnalysisFinding[];
  className?: string;
}) {
  const { data, loading, error, requested, updatedAt, generate, refresh } = useAiSection(
    intent,
    findings,
    { autoLoad: false },
  );
  const hasContent = Boolean(data?.ai_summary);
  const freshness = freshnessText(data, updatedAt);

  return (
    <Card
      title={title}
      action={
        <AnalysisButton
          onClick={hasContent ? refresh : generate}
          loading={loading}
          hasContent={hasContent}
          disabled={!findings.length}
        />
      }
      className={["insights-card", className].filter(Boolean).join(" ")}
    >
      <p className="card-footnote card-footnote--tight">{hint}</p>
      {freshness && <p className="ai-section-meta">{freshness}</p>}
      <div className="insights-card__layout">
        <div className="insights-card__body">
          <SectionBody
            findings={findings}
            loading={loading}
            requested={requested}
            hasContent={hasContent}
            content={data?.ai_summary}
            error={error}
          />
        </div>
      </div>
    </Card>
  );
}

function DecisionBrief({ findings }: { findings: AnalysisFinding[] }) {
  const state = useAiSection("insights", findings);
  const hasContent = Boolean(state.data?.ai_summary);
  const freshness = freshnessText(state.data, state.updatedAt);

  return (
    <>
      <Card
        title="Decision brief"
        action={
          <AnalysisButton
            onClick={hasContent ? state.refresh : state.generate}
            loading={state.loading}
            hasContent={hasContent}
            disabled={!findings.length}
          />
        }
        className="insights-card insights-card--brief"
      >
        <p className="card-footnote card-footnote--tight">{HELP_TEXT.aiInsightsSection}</p>
        {freshness && <p className="ai-section-meta">{freshness}</p>}
        <div className="insights-card__layout">
          <div className="insights-card__body">
            <SectionBody
              findings={findings}
              loading={state.loading}
              requested={state.requested}
              hasContent={hasContent}
              content={state.data?.ai_summary}
              error={state.error}
            />
          </div>
        </div>
      </Card>
      <RiskScoreSection
        findings={findings}
        data={state.data}
        loading={state.loading}
        error={state.error}
      />
    </>
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

/** Uses the deterministic score already included with the decision brief. */
function RiskScoreSection({
  findings,
  data,
  loading,
  error,
}: {
  findings: AnalysisFinding[];
  data: CveAnalysisResponse | null;
  loading: boolean;
  error: string | null;
}) {
  const risk = data?.risk_score;
  const tone = risk ? RATING_COLOR[risk.rating] ?? SEVERITY_COLOR.medium : undefined;

  return (
    <Card title="Risk score" className="insights-card insights-card--score">
      <p className="card-footnote card-footnote--tight">{HELP_TEXT.riskScoreSection}</p>
      {!findings.length && <p className="ai-brief__summary">No findings loaded yet.</p>}
      {findings.length > 0 && loading && !risk && (
        <p className="ai-brief__summary ai-brief__summary--skeleton" aria-live="polite">
          Computing score…
        </p>
      )}
      {findings.length > 0 && !loading && !risk && (
        <p className="ai-brief__summary">{error || "Risk score unavailable — refresh the brief."}</p>
      )}
      {risk && (
        <div className="risk-score-summary">
          <div className="risk-score-badge">
            <span className="risk-score-badge__value" style={{ color: tone }}>
              {risk.score}
            </span>
            <span className="risk-score-badge__rating" style={{ color: tone }}>
              {risk.rating}
            </span>
            <span className="risk-score-badge__confidence">{risk.confidence} confidence</span>
          </div>
          {risk.drivers.length > 0 && (
            <ul className="risk-score-drivers">
              {risk.drivers.map((driver) => (
                <li key={driver.driver}>
                  <strong>{driverLabel(driver.driver)}</strong>
                  <span>{driver.evidence}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}

export function InsightsPage() {
  const { data: dashboard } = useDashboard();
  const { setOpen } = useAskAiUi();

  const findings = useMemo(
    () => toAnalysisFindingsFromData(dashboard, { limit: MAX_FINDINGS_PER_REQUEST }),
    [dashboard],
  );

  return (
    <div className="page page--insights">
      <PageHeader title={NAV_LABELS.insights} subtitle={HELP_TEXT.insightsPage} />

      <div className="insights-bridge">
        <span>Prepared analysis of the current footprint.</span>
        <span>
          Need a specific CVE or follow-up?{" "}
          <button type="button" className="insights-bridge__link" onClick={() => setOpen(true)}>
            Ask AI
          </button>
          .
        </span>
      </div>

      <section className="insights-group" aria-labelledby="insights-decision-heading">
        <header className="insights-group__header">
          <div>
            <h2 id="insights-decision-heading" className="insights-group__title">Decide</h2>
            <p className="insights-group__description">
              Start with the current priorities and the evidence-based risk score.
            </p>
          </div>
          <span className="insights-group__note">Loads one prepared view first</span>
        </header>
        <div className="insights-primary-grid">
          <DecisionBrief findings={findings} />
        </div>
      </section>

      <section className="insights-group" aria-labelledby="insights-evidence-heading">
        <header className="insights-group__header">
          <div>
            <h2 id="insights-evidence-heading" className="insights-group__title">Investigate</h2>
            <p className="insights-group__description">
              Generate only the evidence views needed for the current decision.
            </p>
          </div>
        </header>
        <div className="insights-evidence-grid">
          <AiInsightSection title="Threat intelligence" hint={HELP_TEXT.threatIntelSection} intent="threat_intel" findings={findings} />
          <AiInsightSection title="Top critical findings" hint={HELP_TEXT.criticalFindingsSection} intent="critical_findings" findings={findings} />
          <AiInsightSection title="Highest-risk assets" hint={HELP_TEXT.riskAssetsSection} intent="risk_assets" findings={findings} className="insights-card--wide" />
        </div>
      </section>

      <section className="insights-group" aria-labelledby="insights-action-heading">
        <header className="insights-group__header">
          <div>
            <h2 id="insights-action-heading" className="insights-group__title">Act</h2>
            <p className="insights-group__description">
              Turn the prioritized evidence into an implementation and validation plan.
            </p>
          </div>
        </header>
        <AiInsightSection title="Prioritized remediation" hint={HELP_TEXT.remediateSection} intent="remediate" findings={findings} className="insights-card--remediation" />
      </section>
    </div>
  );
}
