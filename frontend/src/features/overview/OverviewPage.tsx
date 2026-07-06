import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { AtRiskAssets } from "./AtRiskAssets";
import { DashboardPosture } from "./DashboardPosture";
import { CompactRemediationQueue } from "./CompactRemediationQueue";
import { RemediationProgress } from "./RemediationProgress";
import { RiskTrendChart } from "./RiskTrendChart";
import { SeverityDonut } from "./SeverityDonut";

export function OverviewPage() {
  return (
    <div className="page dashboard dashboard--home">
      <PageHeader
        eyebrow="Overview"
        title="Digital Footprint"
        subtitle="External security posture across Fresno State's internet-facing assets."
        action={
          <Link to="/guide" className="view-all-link">
            What do these metrics mean?
          </Link>
        }
      />

      <DashboardPosture />

      <div className="dashboard-home">
        <section className="dashboard-home__severity" aria-label="Severity breakdown">
          <Link to="/cves" className="dashboard__chart-link">
            <SeverityDonut />
          </Link>
        </section>

        <section className="dashboard-home__insight" aria-label="Observation snapshot">
          <RiskTrendChart />
        </section>

        <aside className="dashboard-home__actions" aria-label="Remediation workflow">
          <CompactRemediationQueue limit={4} />
          <RemediationProgress />
        </aside>

        <section className="dashboard-home__assets" aria-label="Highest-risk assets">
          <AtRiskAssets limit={6} />
        </section>
      </div>
    </div>
  );
}
