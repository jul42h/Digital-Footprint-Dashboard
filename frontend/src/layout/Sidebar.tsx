import { NavLink } from "react-router-dom";
import { NavIcon } from "@/components/NavIcon";
import { useLayout } from "@/context/LayoutContext";
import { APP_NAME, APP_TAGLINE, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import type { DerivedData } from "@/lib/adapters";

type NavIconName = "home" | "issues" | "systems" | "fixes" | "providers" | "analytics" | "settings";

const NAV: Array<{
  to: string;
  label: string;
  end: boolean;
  icon: NavIconName;
  count?: (d: DerivedData) => number;
}> = [
  { to: "/", label: NAV_LABELS.home, end: true, icon: "home" },
  { to: "/cves", label: NAV_LABELS.issues, end: false, icon: "issues", count: (d) => d.cves.length },
  { to: "/ips", label: NAV_LABELS.systems, end: false, icon: "systems", count: (d) => d.ips.length },
  {
    to: "/solutions",
    label: NAV_LABELS.fixes,
    end: false,
    icon: "fixes",
    count: (d) => d.solutions.length,
  },
  {
    to: "/vendors",
    label: NAV_LABELS.providers,
    end: false,
    icon: "providers",
    count: (d) => d.vendors.length,
  },
  { to: "/analytics", label: NAV_LABELS.analytics, end: false, icon: "analytics" },
  { to: "/settings", label: NAV_LABELS.settings, end: false, icon: "settings" },
];

export function Sidebar() {
  const { derived } = useDashboard();
  const { sidebarCollapsed, toggleSidebar } = useLayout();

  return (
    <aside
      className={`sidebar${sidebarCollapsed ? " sidebar--collapsed" : ""}`}
      aria-label="Main navigation"
    >
      <div className="sidebar__brand">
        <div className="sidebar__brand-main">
          <span className="sidebar__mark">
            <img
              src="/fresno-seal.png"
              alt="California State University, Fresno seal"
              className="sidebar__mark-img"
              width={40}
              height={40}
            />
          </span>
          {!sidebarCollapsed && (
            <div className="sidebar__brand-text">
              <span className="sidebar__name">{APP_NAME}</span>
              <span className="sidebar__tagline">{APP_TAGLINE}</span>
            </div>
          )}
        </div>
        <button
          type="button"
          className="sidebar__toggle"
          onClick={toggleSidebar}
          title={sidebarCollapsed ? "Expand sidebar ( [ )" : "Collapse sidebar ( [ )"}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!sidebarCollapsed}
        >
          <NavIcon name={sidebarCollapsed ? "menu" : "close"} />
        </button>
      </div>

      <nav className="sidebar__nav">
        {NAV.map((item) => {
          const badge = item.count?.(derived);
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              title={sidebarCollapsed ? item.label : undefined}
              className={({ isActive }) =>
                `sidebar__link${isActive ? " sidebar__link--active" : ""}`
              }
            >
              <span className="sidebar__link-main">
                <NavIcon name={item.icon} />
                {!sidebarCollapsed && <span className="sidebar__link-text">{item.label}</span>}
              </span>
              {badge != null && badge > 0 && (
                <span
                  className={`sidebar__badge${sidebarCollapsed ? " sidebar__badge--dot" : ""}`}
                  aria-label={`${badge} items`}
                >
                  {sidebarCollapsed ? "" : badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}
