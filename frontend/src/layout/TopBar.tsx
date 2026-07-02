import { useEffect } from "react";
import { ThemeSelector } from "@/components/ThemeSelector";
import { NavIcon } from "@/components/NavIcon";
import { useDashboard } from "@/context/DashboardContext";
import { useLayout } from "@/context/LayoutContext";
import { formatRelativeTime } from "@/lib/format";

export function TopBar() {
  const { data, refreshing, reload } = useDashboard();
  const { toggleSidebar } = useLayout();

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
      : data.source === "excel"
        ? "Excel fallback"
        : "No data";

  const isLive = data.source === "api" || data.source === "dynamodb" || data.source === "excel";

  return (
    <header className="topbar">
      <div className="topbar__left">
        <button
          type="button"
          className="topbar__menu"
          onClick={toggleSidebar}
          aria-label="Open navigation menu"
        >
          <NavIcon name="menu" />
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
