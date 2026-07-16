import { lazy, Suspense } from "react";
import { PageHeader } from "@/components/PageHeader";
import { NavIcon } from "@/components/NavIcon";
import { ViewAllLink } from "@/components/ViewAllLink";
import { APP_NAME, HELP_TEXT } from "@/lib/copy";
import { AtRiskAssets } from "./AtRiskAssets";
import { AiBriefStrip } from "./AiBriefStrip";
import { CompactRemediationQueue } from "./CompactRemediationQueue";
import { DashboardPosture } from "./DashboardPosture";
import { PrioritySignals } from "./PrioritySignals";
import { RiskScoreRing } from "./RiskScoreRing";
import { TopCriticalFindings } from "./TopCriticalFindings";

const SeverityDonut = lazy(() =>
  import("./SeverityDonut").then((m) => ({ default: m.SeverityDonut })),
);

/**
 * Home flow: posture counts, then the AI brief as the lead story (what
 * matters and why), then the supporting exposure/severity/signal visuals,
 * then the concrete findings, assets, and remediation queues that back it up.
 */
export function OverviewPage() {
  return (
    <div className="page dashboard dashboard--home dashboard--home-business">
      <PageHeader title={APP_NAME} subtitle={HELP_TEXT.homePage} />

      <DashboardPosture />

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
        <AiBriefStrip variant="business" />
      </section>

      <div className="home-visuals">
        <section className="home-visuals__score home-panel" aria-labelledby="home-exposure-label">
          <h2 id="home-exposure-label" className="home-panel__title">
            Exposure score
          </h2>
          <p className="home-panel__hint">{HELP_TEXT.exposureScore}</p>
          <RiskScoreRing />
        </section>

        <section className="home-visuals__severity" aria-label="Findings by severity">
          <Suspense fallback={<div className="chart-placeholder">Loading…</div>}>
            <SeverityDonut title="Findings by severity" compact />
          </Suspense>
        </section>

        <PrioritySignals />
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
                Priority remediation
              </h2>
              <p className="home-block__lede">{HELP_TEXT.fixFirst}</p>
            </div>
            <ViewAllLink to="/solutions" className="home-block__link" />
          </header>
          <CompactRemediationQueue limit={4} compact hideTitle />
        </section>
      </div>
    </div>
  );
}
