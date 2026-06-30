import { useOutletContext } from 'react-router-dom';
import { DashboardStatsGrid } from '@/components/dashboard/DashboardStatsGrid';
import { RecentVulnerabilities } from '@/components/dashboard/RecentVulnerabilities';
import { SummaryPanel } from '@/components/dashboard/SummaryPanel';
import { TopRiskIPs } from '@/components/dashboard/TopRiskIPs';
//import { CVEsOverTimeChart } from '@/components/charts/CVEsOverTimeChart'; <CVEsOverTimeChart data={charts.cvesOverTime} />
import { OSDistributionChart } from '@/components/charts/OSDistributionChart';
import { PortHeatmap } from '@/components/charts/PortHeatmap';
import { RiskGauge } from '@/components/charts/RiskGauge';
/*import { SeverityByOrgChart } from '@/components/charts/SeverityByOrgChart';<div className="xl:col-span-2">
          <SeverityByOrgChart data={charts.severityByOrg} severities={charts.severities} />
        </div>*/
import { SeverityPieChart } from '@/components/charts/SeverityPieChart';
import { TopIPsBarChart } from '@/components/charts/TopIPsBarChart';
//import { TopOrgsChart } from '@/components/charts/TopOrgsChart';         <TopOrgsChart data={charts.topOrgs} />

import { WorldMapPlaceholder } from '@/components/charts/WorldMapPlaceholder'; 
import type { DashboardData } from '@/types';
import { buildChartData } from '@/utils/chartData';
import { getTopRiskIPs } from '@/utils/dataTransformers';
import { computeNetworkRiskScore, generateExecutiveSummary } from '@/utils/summaryGenerator';

export function DashboardPage() {
  const { data } = useOutletContext<{ data: DashboardData | null }>();
  if (!data) return null;

  const charts = buildChartData(data);
  const summary = generateExecutiveSummary(data.stats, data.ips);
  const riskScore = computeNetworkRiskScore(data.stats);
  const topRiskIPs = getTopRiskIPs(data.ips);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Digital Footprint Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">
           Vulnerability intelligence overview from Shodan data
        </p>
      </div>

      <DashboardStatsGrid stats={data.stats} />
      <SummaryPanel summary={summary} />

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
        <SeverityPieChart data={charts.severityData} />
        <TopIPsBarChart data={charts.topIPs} />
        
        
        <RiskGauge score={riskScore} />
        <PortHeatmap data={charts.portHeatmap} />
        <OSDistributionChart data={charts.osDistribution} />
        <WorldMapPlaceholder data={charts.countries} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <RecentVulnerabilities records={data.cveRecords} />
        <TopRiskIPs ips={topRiskIPs} />
      </div>
    </div>
  );
}
