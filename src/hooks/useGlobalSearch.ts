import { useMemo } from 'react';
import type { DashboardData, IPRecord } from '@/types';

export interface SearchResult {
  type: 'ip' | 'organization' | 'hostname' | 'asn' | 'cve' | 'country';
  label: string;
  value: string;
  ip?: IPRecord;
}

export function useGlobalSearch(data: DashboardData | null, query: string): SearchResult[] {
  return useMemo(() => {
    if (!data || !query.trim()) return [];

    const q = query.trim().toLowerCase();
    const results: SearchResult[] = [];
    const seen = new Set<string>();

    const add = (result: SearchResult) => {
      const key = `${result.type}:${result.value}`;
      if (seen.has(key)) return;
      seen.add(key);
      results.push(result);
    };

    for (const ip of data.ips) {
      if (ip.ip.toLowerCase().includes(q)) {
        add({ type: 'ip', label: ip.ip, value: ip.ip, ip });
      }
      if (ip.organization.toLowerCase().includes(q)) {
        add({ type: 'organization', label: ip.organization, value: ip.organization, ip });
      }
      if (ip.country.toLowerCase().includes(q)) {
        add({ type: 'country', label: ip.country, value: ip.country, ip });
      }
      if (ip.asn?.toLowerCase().includes(q)) {
        add({ type: 'asn', label: ip.asn, value: ip.asn, ip });
      }
      for (const hostname of ip.hostnames) {
        if (hostname.toLowerCase().includes(q)) {
          add({ type: 'hostname', label: hostname, value: hostname, ip });
        }
      }
      for (const cve of ip.cves) {
        if (cve.id.toLowerCase().includes(q)) {
          add({ type: 'cve', label: cve.id, value: cve.id, ip });
        }
      }
    }

    return results.slice(0, 12);
  }, [data, query]);
}
