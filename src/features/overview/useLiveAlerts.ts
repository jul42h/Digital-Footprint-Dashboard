import { useDashboard } from '@/context/DashboardContext';

export function useLiveAlerts(limit = 6) {
  const alerts = useDashboard().derived.alerts;
  return alerts.slice(0, limit);
}
