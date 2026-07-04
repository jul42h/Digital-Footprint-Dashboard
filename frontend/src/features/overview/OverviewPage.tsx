import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { AtRiskAssets } from "./AtRiskAssets";
import { DashboardPosture } from "./DashboardPosture";
import { GeoExposureMap } from "./GeoExposureMap";
import { CompactRemediationQueue } from "./CompactRemediationQueue";
import { HomeTopIpsChart } from "./HomeAnalyticsCharts";
import { RemediationProgress } from "./RemediationProgress";
import { RiskTrendChart } from "./RiskTrendChart";
import { SeverityDonut } from "./SeverityDonut";
import { ThreatDistributionChart } from "./ThreatDistributionChart";

export function OverviewPage() {
  return (
    <div className="page dashboard">
      <PageHeader
        eyebrow="Overview"
        title="Digital Footprint"
        subtitle="Your external security posture at a glance — prioritized by risk across Fresno State's scanned internet-facing assets."
      />

      <DashboardPosture />

      <div className="dashboard-2col dashboard-2col--remediation">
        <RemediationProgress />
        <CompactRemediationQueue limit={5} />
      </div>

      <div className="dashboard-charts-row dashboard-charts-row--triple">
        <Link to="/cves" className="dashboard__chart-link">
          <SeverityDonut />
        </Link>
        <ThreatDistributionChart />
        <RiskTrendChart />
      </div>

      <div className="dashboard-2col dashboard-2col--exposure">
        <GeoExposureMap />
        <HomeTopIpsChart />
      </div>

      <AtRiskAssets limit={5} />
    </div>
  );
}
