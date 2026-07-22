import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { apiUrl, getAccessToken, onSessionExpired, setAccessToken, trySilentRefresh } from "@/lib/api";

export type UserRole = "admin" | "analyst" | "viewer";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  /** True only during the initial startup session check — pages should
   * show a loading state, not the login form, while this is true. */
  initializing: boolean;
  loginError: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function fetchMe(): Promise<AuthUser | null> {
  const token = getAccessToken();
  if (!token) return null;
  try {
    const response = await fetch(apiUrl("/api/v1/auth/me"), {
      headers: { Authorization: `Bearer ${token}` },
      credentials: "same-origin",
    });
    if (!response.ok) return null;
    return (await response.json()) as AuthUser;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [initializing, setInitializing] = useState(true);
  const [loginError, setLoginError] = useState<string | null>(null);

  // Startup session check (spec: "on application startup, check if a valid
  // JWT exists"). The access token is memory-only and never survives a
  // reload, so in practice this means: try the silent refresh once — if the
  // HttpOnly refresh cookie is still good, that's the "valid JWT exists"
  // case; if not, that's "expired" and the user lands on /login.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const refreshed = await trySilentRefresh();
      const me = refreshed ? await fetchMe() : null;
      if (!cancelled) {
        setUser(me);
        setInitializing(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // A 401 surfaced by any authFetch call elsewhere in the app (not just
  // ones made here) means the session is over — drop back to logged-out
  // state so the route guard redirects to /login.
  useEffect(() => onSessionExpired(() => setUser(null)), []);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    setLoginError(null);
    try {
      const response = await fetch(apiUrl("/api/v1/auth/login"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password }),
      });
      const body = await response.json().catch(() => ({}) as Record<string, unknown>);
      if (!response.ok) {
        setLoginError(typeof body.detail === "string" ? body.detail : "Login failed.");
        return false;
      }
      setAccessToken((body as { access_token: string }).access_token);
      const me = await fetchMe();
      setUser(me);
      return true;
    } catch {
      setLoginError("Could not reach the server.");
      return false;
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    const token = getAccessToken();
    try {
      await fetch(apiUrl("/api/v1/auth/logout"), {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        credentials: "same-origin",
      });
    } catch {
      // Best-effort — clear local state regardless of whether the server
      // call succeeded, so the user is never stuck unable to log out.
    }
    setAccessToken(null);
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ user, initializing, loginError, login, logout }),
    [user, initializing, loginError, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
