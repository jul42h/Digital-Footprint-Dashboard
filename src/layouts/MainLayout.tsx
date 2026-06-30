import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import type { DashboardData } from '@/types';

interface MainLayoutProps {
  data: DashboardData | null;
  refreshing: boolean;
  onRefresh: () => void;
}

export function MainLayout({ data, refreshing, onRefresh }: MainLayoutProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.08) 1px, transparent 1px)',
            backgroundSize: '48px 48px',
          }}
        />
      </div>

      <Sidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onToggleCollapse={() => setCollapsed((value) => !value)}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0 relative">
        <Header
          data={data}
          refreshing={refreshing}
          onRefresh={onRefresh}
          onOpenSidebar={() => setMobileOpen(true)}
        />
        <main className="flex-1 p-4 lg:p-6 overflow-auto">
          <Outlet context={{ data }} />
        </main>
      </div>
    </div>
  );
}
