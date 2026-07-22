import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";

/**
 * Role gate for admin-only routes (e.g. /users). Nested inside RequireAuth
 * in router.tsx, which already guarantees `user` is set by the time this
 * renders — this only adds the role check on top. A hidden sidebar link
 * isn't a security boundary on its own; this stops a non-admin from
 * reaching the page by typing the URL directly, matching the same
 * server-side require_admin check the API already enforces.
 */
export function RequireAdmin({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  if (user?.role !== "admin") {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
