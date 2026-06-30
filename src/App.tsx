import { Navigate, Route, Routes } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { useDashboardData } from '@/hooks/useDashboardData';
import { MainLayout } from '@/layouts/MainLayout';
import { AnalyticsPage } from '@/pages/AnalyticsPage';
import { CVEExplorerPage } from '@/pages/CVEExplorerPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { IPAddressPage } from '@/pages/IPAddressPage';
import { SettingsPage } from '@/pages/SettingsPage';

export default function App() {
  const { data, loading, error, refreshing, reload } = useDashboardData();

  if (loading && !data) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="h-8 w-8 text-blue-400 animate-spin" />
          <p className="text-sm text-muted-foreground">Loading Shodan intelligence data...</p>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-6">
        <div className="max-w-md rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-red-400 text-sm">
          {error}
        </div>
      </div>
    );
  }

  return (
    <Routes>
      <Route element={<MainLayout data={data} refreshing={refreshing} onRefresh={reload} />}>
        <Route index element={<DashboardPage />} />
        <Route path="ips" element={<IPAddressPage />} />
        <Route path="cve" element={<CVEExplorerPage />} />
        <Route path="analytics" element={<AnalyticsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
