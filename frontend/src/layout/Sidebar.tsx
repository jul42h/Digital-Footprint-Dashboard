import { NavLink } from "react-router-dom";
import { NavIcon } from "@/components/NavIcon";
import { useLayout } from "@/context/LayoutContext";
import { APP_NAME, APP_TAGLINE, NAV_LABELS } from "@/lib/copy";
import { useDashboard } from "@/context/DashboardContext";
import type { DerivedData } from "@/lib/adapters";

type NavIconName =
  | "home"
  | "insights"
  | "issues"
  | "threats"
  | "systems"
  | "fixes"
  | "providers"
  | "analytics"
  | "guide"
  | "settings";

interface NavItem {
  to: string;
  label: string;
  end: boolean;
  icon: NavIconName;
  count?: (d: DerivedData) => number;
}

interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

/** Grouped for analyst workflow: monitor → investigate → act → reference. */
const NAV_GROUPS: NavGroup[] = [
  {
    id: "monitor",
    label: "Monitor",
    items: [
      { to: "/", label: NAV_LABELS.home, end: true, icon: "home" },
      { to: "/insights", label: NAV_LABELS.insights, end: false, icon: "insights" },
      {
        to: "/cves",
        label: NAV_LABELS.issues,
        end: false,
        icon: "issues",
        count: (d) => d.cves.length,
      },
      {
        to: "/threats",
        label: NAV_LABELS.threats,
        end: false,
        icon: "threats",
        count: (d) => new Set(d.cves.map((c) => c.threatType)).size,
      },
    ],
  },
  {
    id: "investigate",
    label: "Investigate",
    items: [
      {
        to: "/ips",
        label: NAV_LABELS.systems,
        end: false,
        icon: "systems",
        count: (d) => d.ips.length,
      },
      {
        to: "/vendors",
        label: NAV_LABELS.providers,
        end: false,
        icon: "providers",
        count: (d) => d.vendors.length,
      },
      { to: "/analytics", label: NAV_LABELS.analytics, end: false, icon: "analytics" },
    ],
  },
  {
    id: "act",
    label: "Act",
    items: [
      {
        to: "/solutions",
        label: NAV_LABELS.fixes,
        end: false,
        icon: "fixes",
        count: (d) => d.solutions.length,
      },
    ],
  },
  {
    id: "reference",
    label: "Reference",
    items: [
      { to: "/guide", label: NAV_LABELS.guide, end: false, icon: "guide" },
      { to: "/settings", label: NAV_LABELS.settings, end: false, icon: "settings" },
    ],
  },
];

export function Sidebar() {
  const { derived } = useDashboard();
  const { sidebarCollapsed, toggleSidebar, closeSidebarOverlay } = useLayout();

  return (
    <aside
      className={`sidebar${sidebarCollapsed ? " sidebar--collapsed" : ""}`}
      aria-label="Main navigation"
    >
      <div className="sidebar__brand">
        <div className="sidebar__brand-main">
          <img
            className="sidebar__mark"
            src="/fresno-seal.png"
            alt="California State University, Fresno seal"
          />
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
          <NavIcon name={sidebarCollapsed ? "expand" : "collapse"} />
        </button>
      </div>

      <nav className="sidebar__nav">
        {NAV_GROUPS.map((group) => (
          <div key={group.id} className="sidebar__group">
            {!sidebarCollapsed && (
              <p className="sidebar__group-label" id={`nav-${group.id}`}>
                {group.label}
              </p>
            )}
            <div
              className="sidebar__group-links"
              role="group"
              aria-labelledby={sidebarCollapsed ? undefined : `nav-${group.id}`}
              aria-label={sidebarCollapsed ? group.label : undefined}
            >
              {group.items.map((item) => {
                const badge = item.count?.(derived);
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    title={sidebarCollapsed ? item.label : undefined}
                    onClick={closeSidebarOverlay}
                    className={({ isActive }) =>
                      `sidebar__link${isActive ? " sidebar__link--active" : ""}`
                    }
                  >
                    <span className="sidebar__link-main">
                      <NavIcon name={item.icon} />
                      {!sidebarCollapsed && (
                        <span className="sidebar__link-text">{item.label}</span>
                      )}
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
            </div>
          </div>
        ))}
      </nav>
    </aside>
  );
}
