import { useEffect, useState } from "react";

const SHORTCUTS = [
  { keys: "R", action: "Refresh data" },
  { keys: "[", action: "Toggle sidebar" },
  { keys: "?", action: "Show shortcuts" },
  { keys: "Esc", action: "Close dialog" },
] as const;

export function KeyboardShortcutsHelp() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const openHelp = () => setOpen(true);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "?" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("df-show-shortcuts", openHelp);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("df-show-shortcuts", openHelp);
    };
  }, []);

  if (!open) return null;

  return (
    <div className="shortcuts-overlay" role="presentation" onClick={() => setOpen(false)}>
      <div
        className="shortcuts-dialog"
        role="dialog"
        aria-labelledby="shortcuts-title"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="shortcuts-dialog__header">
          <h2 id="shortcuts-title" className="shortcuts-dialog__title">
            Keyboard shortcuts
          </h2>
          <button
            type="button"
            className="btn btn--ghost shortcuts-dialog__close"
            onClick={() => setOpen(false)}
            aria-label="Close"
          >
            ✕
          </button>
        </header>
        <ul className="shortcuts-list">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="shortcuts-list__item">
              <kbd className="shortcuts-list__key">{s.keys}</kbd>
              <span>{s.action}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
