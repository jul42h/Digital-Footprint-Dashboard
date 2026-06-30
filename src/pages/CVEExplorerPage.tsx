import { useOutletContext } from 'react-router-dom';
import { CVEExplorerTable } from '@/components/cve/CVEExplorerTable';
import type { DashboardData } from '@/types';

export function CVEExplorerPage() {
  const { data } = useOutletContext<{ data: DashboardData | null }>();
  if (!data) return null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">CVE Explorer</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Browse, search, and filter all discovered vulnerabilities
        </p>
      </div>
      <CVEExplorerTable records={data.cveRecords} />
    </div>
  );
}
