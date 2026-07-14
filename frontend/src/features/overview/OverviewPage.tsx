import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { QuickStartBanner } from "@/features/onboarding/QuickStartBanner";
import { AtRiskAssets } from "./AtRiskAssets";
import { AiBriefStrip } from "./AiBriefStrip";
import { DashboardPosture } from "./DashboardPosture";
import { CompactRemediationQueue } from "./CompactRemediationQueue";
import { SeverityDonut } from "./SeverityDonut";

export function OverviewPage() {
  return (
    <div className="page dashboard dashboard--home dashboard--home-streamlined">
      <PageHeader
        eyebrow="Overview"
        title="Digital Footprint"
        subtitle="What needs attention across Fresno State's external assets."
        action={
          <Link to="/guide" className="view-all-link">
            Guide
          </Link>
        }
      />

      <QuickStartBanner />
      <DashboardPosture />
      <AiBriefStrip />

      <div className="dashboard-home dashboard-home--streamlined">
        <section className="dashboard-home__severity" aria-label="Severity breakdown">
          <Link to="/cves" className="dashboard__chart-link">
            <SeverityDonut />
          </Link>
        </section>

        <aside className="dashboard-home__actions" aria-label="What to fix first">
          <CompactRemediationQueue limit={5} compact />
        </aside>

        <section className="dashboard-home__assets" aria-label="Highest-risk assets">
          <AtRiskAssets limit={5} compact />
        </section>
      </div>
    </div>
  );
}
