const API_BASE = import.meta.env.VITE_API_URL ?? "";

export function getApiBaseUrl(): string {
  return API_BASE.replace(/\/$/, "");
}

export function apiUrl(path: string): string {
  const base = getApiBaseUrl();
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return base ? `${base}${normalized}` : normalized;
}

// ---------------------------------------------------------------------------
// Access token (in-memory only — never localStorage/sessionStorage, so an
// XSS payload can't read it off disk). A page reload loses it on purpose;
// AuthProvider re-establishes it via a silent refresh using the HttpOnly
// refresh cookie the browser still holds.
// ---------------------------------------------------------------------------

let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

type Listener = () => void;
const sessionExpiredListeners = new Set<Listener>();

/** AuthProvider subscribes so a 401 surfaced by *any* authFetch call in the
 * app (not just ones AuthProvider itself made) still clears its React state
 * and lets the route guard redirect back to /login. */
export function onSessionExpired(listener: Listener): () => void {
  sessionExpiredListeners.add(listener);
  return () => sessionExpiredListeners.delete(listener);
}

function notifySessionExpired(): void {
  accessToken = null;
  sessionExpiredListeners.forEach((listener) => listener());
}

let inFlightRefresh: Promise<boolean> | null = null;

/**
 * Silently trade the HttpOnly refresh cookie for a new access token.
 * Returns false (never throws) if there's no valid session — callers treat
 * that as "not logged in", not as an error to surface.
 *
 * De-duplicated via a single in-flight promise: on first page load,
 * AuthProvider's own startup check and any authFetch call already in flight
 * (e.g. the dashboard's initial health check) can race to refresh at
 * nearly the same instant. Without this, both would fire a real HTTP
 * request against the same one-time-use refresh token, and one would fail
 * for no reason. Every caller during that window shares this one request.
 */
export async function trySilentRefresh(): Promise<boolean> {
  if (inFlightRefresh) return inFlightRefresh;

  inFlightRefresh = (async () => {
    try {
      const response = await fetch(apiUrl("/api/v1/auth/refresh"), {
        method: "POST",
        credentials: "same-origin",
      });
      if (!response.ok) return false;
      const data = (await response.json()) as { access_token: string };
      setAccessToken(data.access_token);
      return true;
    } catch {
      return false;
    } finally {
      inFlightRefresh = null;
    }
  })();

  return inFlightRefresh;
}

/** Extract a readable message from a FastAPI/Pydantic error response body —
 * `detail` can be a plain string or a list of validation-error objects. */
export function parseApiError(bodyText: string, fallback: string): string {
  try {
    const parsed = JSON.parse(bodyText) as { detail?: unknown; error?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
    if (typeof parsed.error === "string") return parsed.error;
    if (Array.isArray(parsed.detail)) {
      return parsed.detail
        .map((item) =>
          typeof item === "object" && item && "msg" in item
            ? String((item as { msg: string }).msg)
            : String(item),
        )
        .join("; ");
    }
  } catch {
    /* use raw text */
  }
  return bodyText || fallback;
}

/**
 * fetch() wrapper used by every API call in the app. Attaches the current
 * access token, and on a 401 makes exactly one attempt to silently refresh
 * and retry — if that also fails, notifies AuthProvider so the UI drops
 * back to the login screen instead of showing a broken authenticated page.
 */
export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const attempt = (token: string | null) => {
    const headers = new Headers(init.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(apiUrl(path), { ...init, headers, credentials: "same-origin" });
  };

  let response = await attempt(getAccessToken());

  if (response.status === 401) {
    const refreshed = await trySilentRefresh();
    if (refreshed) {
      response = await attempt(getAccessToken());
    } else {
      notifySessionExpired();
    }
  }

  return response;
}
