import { NavLink } from "react-router-dom";
import { APP_NAME, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import type { DerivedData } from "@/lib/adapters";

const NAV: Array<{
  to: string;
  label: string;
  end: boolean;
  count?: (d: DerivedData) => number;
}> = [
  { to: "/", label: NAV_LABELS.home, end: true },
  { to: "/cves", label: NAV_LABELS.issues, end: false, count: (d) => d.cves.length },
  { to: "/ips", label: NAV_LABELS.systems, end: false, count: (d) => d.ips.length },
  { to: "/solutions", label: NAV_LABELS.fixes, end: false, count: (d) => d.solutions.length },
  { to: "/vendors", label: NAV_LABELS.providers, end: false, count: (d) => d.vendors.length },
  { to: "/analytics", label: NAV_LABELS.analytics, end: false },
  { to: "/settings", label: NAV_LABELS.settings, end: false },
];

export function Sidebar() {
  const { derived } = useDashboard();

  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__mark" />
        <span className="sidebar__name">{APP_NAME}</span>
      </div>

      <nav className="sidebar__nav">
        {NAV.map((item) => {
          const badge = item.count?.(derived);
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `sidebar__link${isActive ? " sidebar__link--active" : ""}`
              }
            >
              <span>{item.label}</span>
              {badge != null && badge > 0 && (
                <span className="sidebar__badge">{badge}</span>
              )}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}
