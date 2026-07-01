import { createContext, useContext } from 'react';
import type { DerivedData } from '@/lib/adapters';
import type { DashboardData } from '@/types/data';

export interface DashboardContextValue {
  data: DashboardData;
  derived: DerivedData;
  loading: boolean;
  error: string | null;
  refreshing: boolean;
  reload: () => void;
}

export const DashboardContext = createContext<DashboardContextValue | null>(null);

export function useDashboard(): DashboardContextValue {
  const ctx = useContext(DashboardContext);
  if (!ctx) {
    throw new Error('useDashboard must be used within DashboardProvider');
  }
  return ctx;
}
