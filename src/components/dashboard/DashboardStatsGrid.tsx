import {
  AlertTriangle,
  Building2,
  Calendar,
  /*Globe2      <StatCard title="Unique Countries" value={stats.uniqueCountries} icon={Globe2} />
 ,*/
  Network,
  Shield,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react';
import type { DashboardStats } from '@/types';
import { formatDate } from '@/utils/dateUtils';
import { StatCard } from './StatCard';

interface DashboardStatsGridProps {
  stats: DashboardStats;
}

export function DashboardStatsGrid({ stats }: DashboardStatsGridProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-6 gap-4">
      <StatCard title="Total IP Addresses" value={stats.totalIPs} icon={Network} />
      <StatCard title="Total CVEs" value={stats.totalCVEs} icon={ShieldAlert} accent="orange" />
      <StatCard title="Critical CVEs" value={stats.criticalCVEs} icon={AlertTriangle} accent="red" />
      <StatCard title="High CVEs" value={stats.highCVEs} icon={Shield} accent="orange" />
      <StatCard title="Medium CVEs" value={stats.mediumCVEs} icon={Shield} accent="yellow" />
      <StatCard title="Low CVEs" value={stats.lowCVEs} icon={Shield} accent="blue" />
      <StatCard title="Avg CVSS Score" value={stats.averageCVSS} icon={TrendingUp} />
      <StatCard title="Highest CVSS" value={stats.highestCVSS} icon={AlertTriangle} accent="red" />
      <StatCard
        title="Newest Vulnerability"
        value={formatDate(stats.newestVulnerability ?? undefined)}
        icon={Calendar}
        subtitle="Most recent CVE publish date"
      />
      <StatCard
        title="Oldest Vulnerability"
        value={formatDate(stats.oldestVulnerability ?? undefined)}
        icon={Calendar}
        subtitle="Earliest CVE in dataset"
      />
      <StatCard title="Unique Organizations" value={stats.uniqueOrganizations} icon={Building2} />
    </div>
  );
}
