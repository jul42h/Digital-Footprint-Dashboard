import { useEffect, useState } from "react";
import { ANALYZE_HINT_STORAGE_KEY } from "./quickStart";

function isDismissed(): boolean {
  try {
    return localStorage.getItem(ANALYZE_HINT_STORAGE_KEY) === "1";
  } catch {
    return true;
  }
}

/** Soft callout near the Analyze FAB — shown once, easy to dismiss. */
export function AnalyzeFabHint({ panelOpen }: { panelOpen: boolean }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (panelOpen) {
      setVisible(false);
      return;
    }
    const id = window.setTimeout(() => {
      if (!isDismissed()) setVisible(true);
    }, 1200);
    return () => window.clearTimeout(id);
  }, [panelOpen]);

  if (!visible || panelOpen) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(ANALYZE_HINT_STORAGE_KEY, "1");
    } catch {
      /* ignore */
    }
    setVisible(false);
  };

  return (
    <div className="analyze-hint" role="status">
      <p className="analyze-hint__text">
        Optional AI: pick a few CVEs for a deeper write-up. Priority brief lives on Home.
      </p>
      <button type="button" className="analyze-hint__dismiss" onClick={dismiss} aria-label="Dismiss tip">
        Got it
      </button>
    </div>
  );
}
