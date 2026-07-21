import { useMemo } from 'react';
import { useDashboard } from '@/context/DashboardContext';
import { useRemediation } from '@/context/RemediationContext';

export function useSolutions() {
  const solutions = useDashboard().derived.solutions;
  const { applyOverrides } = useRemediation();
  return useMemo(() => applyOverrides(solutions), [solutions, applyOverrides]);
}
