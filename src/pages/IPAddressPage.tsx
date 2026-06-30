import { useOutletContext } from 'react-router-dom';
import { IPAddressTable } from '@/components/ip/IPAddressTable';
import type { DashboardData } from '@/types';

export function IPAddressPage() {
  const { data } = useOutletContext<{ data: DashboardData | null }>();
  if (!data) return null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">IP Address Table</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Searchable inventory of discovered hosts with vulnerability metrics
        </p>
      </div>
      <IPAddressTable ips={data.ips} />
    </div>
  );
}
