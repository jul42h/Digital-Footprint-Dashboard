import { useDashboard } from '@/context/DashboardContext';

export function useVendors() {
  return useDashboard().derived.vendors;
}

export function useVendor(id: string) {
  return useDashboard().derived.vendors.find((v) => v.id === id);
}

export function useProducts() {
  return useDashboard().derived.products;
}

export function useProductsForVendor(vendorId: string) {
  return useDashboard().derived.products.filter((p) => p.vendorId === vendorId);
}
