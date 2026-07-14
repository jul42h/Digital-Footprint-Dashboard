import { useEffect } from "react";
import { ThemeSelector } from "@/components/ThemeSelector";
import { useDashboard } from "@/context/DashboardContext";
import { useLayout } from "@/context/LayoutContext";
import { formatRelativeTime } from "@/lib/format";

export function TopBar() {
  const { data, refreshing, reload } = useDashboard();
  const { toggleSidebar, sidebarOverlayOpen } = useLayout();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== "r") return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      e.preventDefault();
      reload();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [reload]);

  const sourceLabel =
    data.source === "api" || data.source === "dynamodb"
      ? "API · DynamoDB"
      : "No data";

  const isLive = data.source === "api" || data.source === "dynamodb";

  return (
    <header className="topbar">
      <div className="topbar__left">
        <button
          type="button"
          className="topbar__menu-btn"
          onClick={toggleSidebar}
          aria-label={sidebarOverlayOpen ? "Close navigation menu" : "Open navigation menu"}
          aria-expanded={sidebarOverlayOpen}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden fill="none">
            <path
              d="M3 6h18M3 12h18M3 18h18"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </button>
        <span className="topbar__status">
          <span className={`topbar__dot${isLive ? " topbar__dot--live" : ""}`} />
          {sourceLabel}
          {data.lastUpdated && (
            <span className="topbar__updated">· {formatRelativeTime(data.lastUpdated)}</span>
          )}
        </span>
      </div>
      <div className="topbar__actions">
        <button
          type="button"
          className="btn btn--compact"
          onClick={reload}
          disabled={refreshing}
          title="Refresh data (R)"
          aria-label="Refresh data"
        >
          <span className="topbar__refresh-icon" aria-hidden>
            ↻
          </span>
          <span className="topbar__refresh-label">{refreshing ? "…" : "Refresh"}</span>
        </button>
        <ThemeSelector />
        <button
          type="button"
          className="btn btn--ghost"
          title="Show quick start tips"
          aria-label="Show quick start tips"
          onClick={() => window.dispatchEvent(new Event("df-show-quickstart"))}
        >
          Tips
        </button>
        <button
          type="button"
          className="btn btn--ghost"
          title="Keyboard shortcuts (?)"
          aria-label="Keyboard shortcuts"
          onClick={() => window.dispatchEvent(new Event("df-show-shortcuts"))}
        >
          ?
        </button>
      </div>
    </header>
  );
}
