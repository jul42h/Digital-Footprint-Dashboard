import { DashboardContext } from "@/context/DashboardContext";
import { useDashboardData } from "@/hooks/useDashboardData";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";

function DashboardShell() {
  const state = useDashboardData();

  if (state.loading && !state.data) {
    return (
      <div style={{ height: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ color: "var(--text-secondary)", fontSize: 14 }}>Loading Shodan intelligence data…</p>
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

  if (!state.data || !state.derived) return null;

  return (
    <DashboardContext.Provider
      value={{
        data: state.data,
        derived: state.derived,
        loading: state.loading,
        error: state.error,
        refreshing: state.refreshing,
        reload: state.reload,
      }}
    >
      <RouterProvider router={router} />
    </DashboardContext.Provider>
  );
}

export function App() {
  return <DashboardShell />;
}
