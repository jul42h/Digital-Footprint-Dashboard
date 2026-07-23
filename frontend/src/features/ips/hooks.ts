import { useDashboard } from '@/context/DashboardContext';

export function useIps() {
  return useDashboard().derived.ips;
}

export function useIp(id: string) {
  return useDashboard().derived.ips.find((ip) => ip.id === id);
}
