import { useCallback, useEffect, useMemo, useState } from 'react';
import type { DashboardData } from '@/types/data';
import { deriveDashboardViews } from '@/lib/adapters';
import { loadDashboardData, reloadDashboardData } from '@/services/excelLoader';

export function useDashboardData() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      setError(null);
      const result = isRefresh ? await reloadDashboardData() : await loadDashboardData();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const derived = useMemo(
    () => (data ? deriveDashboardViews(data) : null),
    [data],
  );

  return { data, derived, loading, error, refreshing, reload: () => load(true) };
}
