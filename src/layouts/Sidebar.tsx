import { NavLink } from 'react-router-dom';
import {
  /*BarChart3,*/
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  Network,
  Settings,
  ShieldAlert,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/ips', label: 'IP Address Table', icon: Network },
  { to: '/cve', label: 'CVE Explorer', icon: ShieldAlert },
  //{ to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings },
];

interface SidebarProps {
  collapsed: boolean;
  mobileOpen: boolean;
  onToggleCollapse: () => void;
  onCloseMobile: () => void;
}

export function Sidebar({ collapsed, mobileOpen, onToggleCollapse, onCloseMobile }: SidebarProps) {
  return (
    <>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={onCloseMobile} />
      )}

      <aside
        className={cn(
          'fixed lg:sticky top-0 z-50 h-screen border-r border-border bg-card/95 backdrop-blur-md transition-all duration-200 flex flex-col',
          collapsed ? 'w-[72px]' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
        )}
      >
        <div className="flex items-center justify-between p-4 border-b border-border">
          {!collapsed && (
            <div>
              <div className="text-sm font-bold text-blue-400 tracking-wide">Digital Footprint</div>
            </div>
          )}
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="icon" className="hidden lg:flex h-8 w-8" onClick={onToggleCollapse}>
              {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            </Button>
            <Button variant="ghost" size="icon" className="lg:hidden h-8 w-8" onClick={onCloseMobile}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={onCloseMobile}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors',
                  isActive
                    ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  collapsed && 'justify-center px-2',
                )
              }
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        {!collapsed && (
          <div className="p-4 border-t border-border text-[10px] text-muted-foreground">
            Prototype UI · Excel data source
          </div>
        )}
      </aside>
    </>
  );
}
