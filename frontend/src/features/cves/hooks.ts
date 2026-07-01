import { useDashboard } from '@/context/DashboardContext';

export function useCves() {
  return useDashboard().derived.cves;
}

export function useCve(id: string) {
  return useDashboard().derived.cves.find((c) => c.id === id);
}
