import { useAskAiUi } from "@/features/ask-ai/AskAiContext";
import { PageHeader } from "@/components/PageHeader";
import { NavIcon } from "@/components/NavIcon";
import { ViewAllLink } from "@/components/ViewAllLink";
import { APP_NAME, HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { AtRiskAssets } from "./AtRiskAssets";
import { AiBriefStrip } from "./AiBriefStrip";
import { CompactRemediationQueue } from "./CompactRemediationQueue";
import { DashboardPosture } from "./DashboardPosture";
import { PrioritySignals } from "./PrioritySignals";
import { RiskScoreRing } from "./RiskScoreRing";
import { TopCriticalFindings } from "./TopCriticalFindings";

/**
 * Home = AI Risk Intelligence command center.
 * Lead with the AI brief, then risk score + threat signals, then the findings,
 * assets, and remediation queues analysts act on next — not a raw data browser.
 */
export function OverviewPage() {
  const { setOpen } = useAskAiUi();

  return (
    <div className="page dashboard dashboard--home dashboard--home-business">
      <PageHeader title={APP_NAME} subtitle={HELP_TEXT.homePage} />

      <section
        className="home-brief-block home-brief-block--hero home-block"
        aria-labelledby="home-brief-label"
      >
        <header className="home-block__head">
          <div className="home-block__heading">
            <span className="home-block__icon" aria-hidden>
              <NavIcon name="insights" />
            </span>
            <div>
              <h2 id="home-brief-label" className="home-block__title">
                AI risk summary
              </h2>
              <p className="home-block__lede">{HELP_TEXT.aiBrief}</p>
            </div>
          </div>
          <ViewAllLink to="/insights" className="home-block__link">
            Full AI Risk Intelligence
          </ViewAllLink>
        </header>
        <AiBriefStrip />
      </section>

      <div className="home-command">
        <section className="home-visuals__score home-panel" aria-labelledby="home-risk-label">
          <h2 id="home-risk-label" className="home-panel__title">
            Risk score
          </h2>
          <p className="home-panel__hint">{HELP_TEXT.riskScoreHome}</p>
          <RiskScoreRing />
        </section>

        <div className="home-command__side">
          <DashboardPosture />
          <PrioritySignals />
        </div>
      </div>

      <section className="home-block" aria-labelledby="home-critical-label">
        <header className="home-block__head">
          <div>
            <h2 id="home-critical-label" className="home-block__title">
              Top critical findings
            </h2>
            <p className="home-block__lede">{HELP_TEXT.topCriticalFindings}</p>
          </div>
          <ViewAllLink to="/cves" className="home-block__link" />
        </header>
        <TopCriticalFindings />
      </section>

      <div className="home-focus">
        <section className="home-block" aria-labelledby="home-assets-label">
          <header className="home-block__head">
            <div>
              <h2 id="home-assets-label" className="home-block__title">
                Highest-risk assets
              </h2>
              <p className="home-block__lede">{HELP_TEXT.atRiskAssets}</p>
            </div>
            <ViewAllLink to="/ips" className="home-block__link" />
          </header>
          <AtRiskAssets limit={4} compact hideTitle />
        </section>

        <section className="home-block" aria-labelledby="home-fix-label">
          <header className="home-block__head">
            <div>
              <h2 id="home-fix-label" className="home-block__title">
                Prioritized remediation
              </h2>
              <p className="home-block__lede">{HELP_TEXT.fixFirst}</p>
            </div>
            <ViewAllLink to="/solutions" className="home-block__link" />
          </header>
          <CompactRemediationQueue limit={4} compact hideTitle />
        </section>
      </div>

      <section className="home-actions" aria-labelledby="home-actions-label">
        <header className="home-block__head">
          <div>
            <h2 id="home-actions-label" className="home-block__title">
              Next actions
            </h2>
            <p className="home-block__lede">{HELP_TEXT.homeNextActions}</p>
          </div>
        </header>
        <div className="home-actions__row">
          <ViewAllLink to="/insights" className="home-actions__btn">
            {NAV_LABELS.insights}
          </ViewAllLink>
          <button
            type="button"
            className="home-actions__btn home-actions__btn--secondary"
            onClick={() => setOpen(true)}
          >
            Ask AI
          </button>
          <ViewAllLink to="/solutions" className="home-actions__btn home-actions__btn--secondary">
            Track remediations
          </ViewAllLink>
        </div>
      </section>
    </div>
  );
}
