import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, type Location } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { APP_NAME, APP_TAGLINE } from "@/lib/copy";

export function LoginPage() {
  const { user, initializing, login, loginError } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Already logged in (e.g. navigated here directly) — bounce straight to
  // wherever they came from, or Home.
  if (!initializing && user) {
    const from = (location.state as { from?: Location } | null)?.from;
    return <Navigate to={from ? `${from.pathname}${from.search}` : "/"} replace />;
  }

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!username.trim() || !password || submitting) return;
    setSubmitting(true);
    const ok = await login(username.trim(), password);
    if (ok) {
      const from = (location.state as { from?: Location } | null)?.from;
      // A full navigation (not react-router's client-side navigate) is
      // deliberate here: the dashboard's own data-loading hook only fetches
      // once, on mount, and ran before this login existed — it needs to
      // remount with the now-valid session to actually load real data
      // instead of the empty pre-login fallback it's currently showing.
      window.location.href = from ? `${from.pathname}${from.search}` : "/";
      return;
    }
    setSubmitting(false);
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <img className="auth-brand__mark" src="/fresno-seal.png" alt="California State University, Fresno seal" />
          <div>
            <p className="auth-brand__name">{APP_NAME}</p>
            <p className="auth-brand__tagline">{APP_TAGLINE}</p>
          </div>
        </div>

        <h1 className="auth-title">Sign in</h1>

        <form className="auth-form" onSubmit={onSubmit}>
          <label className="auth-field">
            <span className="auth-label">Username</span>
            <input
              className="auth-input"
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={submitting}
              required
            />
          </label>

          <label className="auth-field">
            <span className="auth-label">Password</span>
            <input
              className="auth-input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
              required
            />
          </label>

          {loginError && <p className="auth-error">{loginError}</p>}

          <button type="submit" className="btn btn--primary auth-submit" disabled={submitting}>
            {submitting ? "Signing in…" : "Log in"}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/forgot-password">Forgot password?</Link>
        </div>
      </div>
    </div>
  );
}
