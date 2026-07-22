import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { apiUrl } from "@/lib/api";
import { APP_NAME, APP_TAGLINE } from "@/lib/copy";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!email.trim() || submitting) return;
    setSubmitting(true);
    try {
      // No auth token needed — this endpoint is intentionally reachable
      // while logged out, and the backend is currently a placeholder
      // (records the request, doesn't send an email yet).
      const response = await fetch(apiUrl("/api/v1/auth/forgot-password"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const body = await response.json().catch(() => ({}) as Record<string, unknown>);
      setMessage(
        typeof body.message === "string"
          ? body.message
          : "If that email is registered, password reset instructions have been sent.",
      );
    } catch {
      setMessage("Could not reach the server. Try again shortly.");
    } finally {
      setSubmitting(false);
    }
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

        <h1 className="auth-title">Reset your password</h1>

        {message ? (
          <p className="auth-message">{message}</p>
        ) : (
          <form className="auth-form" onSubmit={onSubmit}>
            <label className="auth-field">
              <span className="auth-label">Email</span>
              <input
                className="auth-input"
                type="email"
                autoComplete="email"
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={submitting}
                required
              />
            </label>
            <button type="submit" className="btn btn--primary auth-submit" disabled={submitting}>
              {submitting ? "Sending…" : "Send reset instructions"}
            </button>
          </form>
        )}

        <div className="auth-links">
          <Link to="/login">Back to sign in</Link>
        </div>
      </div>
    </div>
  );
}
