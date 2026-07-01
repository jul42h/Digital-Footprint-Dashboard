import { useEffect, useState } from "react";
import { useDashboard } from "@/context/DashboardContext";
import { formatRelativeTime } from "@/lib/format";

type Theme = "light" | "dark";

const THEME_KEY = "df-dashboard-theme";

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem(THEME_KEY) as Theme | null;
    if (stored === "light" || stored === "dark") return stored;
    return (document.documentElement.getAttribute("data-theme") as Theme) || "dark";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

export function TopBar() {
  const [theme, toggleTheme] = useTheme();
  const { data, refreshing, reload } = useDashboard();

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
          className="btn"
          onClick={reload}
          disabled={refreshing}
          title="Refresh data (R)"
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
        <button
          type="button"
          className="btn btn--ghost"
          onClick={toggleTheme}
          aria-label="Toggle theme"
          title="Toggle light/dark theme"
        >
          {theme === "dark" ? "☀ Light" : "☾ Dark"}
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
