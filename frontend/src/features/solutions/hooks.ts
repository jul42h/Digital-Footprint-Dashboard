import { useDashboard } from '@/context/DashboardContext';

export function useSolutions() {
  return useDashboard().derived.solutions;
}

export function useSolutionsForCve(cveId: string) {
  return useDashboard().derived.solutions.filter((s) => s.cveId === cveId);
}
