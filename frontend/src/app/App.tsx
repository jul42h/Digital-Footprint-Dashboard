import { useMemo } from "react";
import { DashboardContext } from "@/context/DashboardContext";
import { RemediationProvider } from "@/context/RemediationContext";
import { useDashboardData } from "@/hooks/useDashboardData";
import { HELP_TEXT } from "@/lib/copy";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";

function DashboardShell() {
  const state = useDashboardData();

  const value = useMemo(
    () =>
      state.data && state.derived
        ? {
            data: state.data,
            derived: state.derived,
            loading: state.loading,
            error: state.error,
            refreshing: state.refreshing,
            reload: state.reload,
          }
        : null,
    [state.data, state.derived, state.loading, state.error, state.refreshing, state.reload],
  );

  if (state.loading && !state.data) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ color: "var(--text-secondary)", fontSize: 14 }}>{HELP_TEXT.loading}</p>
      </div>
    );
  }

  if (state.error && !state.data) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <p style={{ color: "var(--sev-critical)", fontSize: 14 }}>{state.error}</p>
      </div>
    );
  }

  if (!value) return null;

  return (
    <DashboardContext.Provider value={value}>
      <RemediationProvider>
        <RouterProvider router={router} />
      </RemediationProvider>
    </DashboardContext.Provider>
  );
}

export function App() {
  return <DashboardShell />;
}
