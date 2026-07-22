import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";

/**
 * Gate for every route that requires being logged in (spec: "users who are
 * not logged in should never access Dashboard, Asset pages, Findings, Map,
 * AI Summary, Settings"). Wraps the whole authenticated route tree in
 * router.tsx rather than each page individually.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, initializing } = useAuth();
  const location = useLocation();

  if (initializing) {
    return (
      <div className="auth-page">
        <p className="auth-loading">Checking your session…</p>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <>{children}</>;
}
