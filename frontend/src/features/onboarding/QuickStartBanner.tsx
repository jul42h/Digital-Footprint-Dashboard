import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { QUICK_START_STEPS, QUICK_START_STORAGE_KEY } from "./quickStart";

function isDismissed(): boolean {
  try {
    return localStorage.getItem(QUICK_START_STORAGE_KEY) === "1";
  } catch {
    return true;
  }
}

function dismiss(): void {
  try {
    localStorage.setItem(QUICK_START_STORAGE_KEY, "1");
  } catch {
    /* ignore */
  }
}

/** Compact first-run guide — dismissible, not a blocking modal. */
export function QuickStartBanner() {
  const [visible, setVisible] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setVisible(!isDismissed());
    const show = () => {
      try {
        localStorage.removeItem(QUICK_START_STORAGE_KEY);
      } catch {
        /* ignore */
      }
      setVisible(true);
      setExpanded(true);
    };
    window.addEventListener("df-show-quickstart", show);
    return () => window.removeEventListener("df-show-quickstart", show);
  }, []);

  if (!visible) return null;

  const close = () => {
    dismiss();
    setVisible(false);
  };

  return (
    <aside className="quick-start" aria-label="Quick start">
      <div className="quick-start__bar">
        <div className="quick-start__lead">
          <span className="quick-start__eyebrow">Quick start</span>
          <p className="quick-start__title">New here? A short path through the dashboard.</p>
        </div>
        <div className="quick-start__actions">
          <button
            type="button"
            className="quick-start__toggle"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
          >
            {expanded ? "Hide steps" : "Show steps"}
          </button>
          <button type="button" className="quick-start__dismiss" onClick={close}>
            Dismiss
          </button>
        </div>
      </div>

      {expanded && (
        <ol className="quick-start__steps">
          {QUICK_START_STEPS.map((step, index) => (
            <li key={step.id} className="quick-start__step">
              <span className="quick-start__num" aria-hidden>
                {index + 1}
              </span>
              <div>
                <Link to={step.to} className="quick-start__step-title">
                  {step.title}
                </Link>
                <p className="quick-start__step-body">{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </aside>
  );
}
