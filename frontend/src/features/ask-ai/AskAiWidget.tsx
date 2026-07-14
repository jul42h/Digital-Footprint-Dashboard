import { useEffect, useRef, useState } from "react";
import { useCves } from "@/features/cves/hooks";
import { ChatMessageBubble, TypingIndicator } from "./ChatMessage";
import { useAskAiUi } from "./AskAiContext";
import { useCveAnalysisChat } from "./useAskAiChat";
import { pickKevCveIds, pickPriorityCveIds } from "./cveSelection";
import {
  ANALYZE_PRESETS,
  MAX_CVE_IDS_PER_REQUEST,
  type AnalysisIntent,
} from "./types";

type PanelIntent = (typeof ANALYZE_PRESETS)[number]["id"];

export function AskAiWidget() {
  const { open, setOpen, pendingCveIds, consumePendingCveIds } = useAskAiUi();

  return (
    <div className={`ask-ai-widget${open ? " ask-ai-widget--open" : ""}`}>
      {open && (
        <AskAiPanel
          pendingCveIds={pendingCveIds}
          consumePendingCveIds={consumePendingCveIds}
          onClose={() => setOpen(false)}
        />
      )}

      <button
        type="button"
        className={`ask-ai-fab${open ? " ask-ai-fab--active" : ""}`}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={open ? "Close Analyze" : "Open Analyze"}
        title="Analyze"
      >
        {open ? (
          <span aria-hidden>✕</span>
        ) : (
          <>
            <AnalyzeIcon />
            <span className="ask-ai-fab__label">Analyze</span>
          </>
        )}
      </button>
    </div>
  );
}

function AnalyzeIcon() {
  return (
    <span className="ask-ai-fab__icon" aria-hidden>
      <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.85">
        <path
          d="M5 6.5A2.5 2.5 0 017.5 4h9A2.5 2.5 0 0119 6.5v6A2.5 2.5 0 0116.5 15H11l-3.5 3v-3H7.5A2.5 2.5 0 015 12.5v-6z"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </span>
  );
}

function AskAiPanel({
  pendingCveIds,
  consumePendingCveIds,
  onClose,
}: {
  pendingCveIds: string[] | null;
  consumePendingCveIds: () => string[] | null;
  onClose: () => void;
}) {
  const cves = useCves();
  const {
    messages,
    selectedIds,
    loading,
    error,
    analyze,
    clearChat,
    toggleCveId,
    setSelectedIdsCap,
  } = useCveAnalysisChat();

  const [intent, setIntent] = useState<PanelIntent>("analyze");
  const scrollerRef = useRef<HTMLDivElement>(null);
  // Deep-link from Home / Priority signals: preselect findings (user runs analysis).
  useEffect(() => {
    if (!pendingCveIds?.length) return;
    const ids = consumePendingCveIds();
    if (!ids?.length) return;
    setSelectedIdsCap(ids);
  }, [pendingCveIds, consumePendingCveIds, setSelectedIdsCap]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, loading]);

  const picks = pickPriorityCveIds(cves, MAX_CVE_IDS_PER_REQUEST);
  const kevAvailable = pickKevCveIds(cves, 1).length > 0;
  const canRun = selectedIds.length > 0 && !loading;

  const run = () => {
    if (!canRun) return;
    void analyze(selectedIds, intent as AnalysisIntent);
  };

  return (
    <section className="ask-ai-panel" role="dialog" aria-label="Analyze findings">
      <header className="ask-ai-panel__header">
        <div>
          <h2 className="ask-ai-panel__title">Analyze</h2>
          <p className="ask-ai-panel__sub">Risk insights for selected findings</p>
        </div>
        <div className="ask-ai-panel__header-actions">
          <button
            type="button"
            className="ask-ai-panel__ghost"
            onClick={clearChat}
            disabled={loading || (messages.length === 0 && selectedIds.length === 0)}
          >
            Clear
          </button>
          <button type="button" className="ask-ai-panel__ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
      </header>

      <div className="ask-ai-panel__thread" ref={scrollerRef}>
        {messages.length === 0 && !loading ? (
          <div className="ask-ai-empty">
            <p className="ask-ai-empty__title">Get started</p>
            <ol className="ask-ai-empty__steps">
              <li>Select findings below</li>
              <li>Choose Risk, Fix, or Next</li>
              <li>Run analysis</li>
            </ol>
          </div>
        ) : (
          messages.map((msg) => <ChatMessageBubble key={msg.id} message={msg} />)
        )}
        {loading && <TypingIndicator />}
      </div>

      {error && !loading && <p className="ask-ai-error">{error}</p>}

      <footer className="ask-ai-panel__footer">
        <div className="ask-ai-footer__block">
          <div className="ask-ai-footer__label-row">
            <span className="ask-ai-footer__label">Findings</span>
            <span className="ask-ai-footer__meta">
              {selectedIds.length}/{MAX_CVE_IDS_PER_REQUEST}
            </span>
          </div>
          <div className="ask-ai-footer__shortcuts">
            <button
              type="button"
              className="ask-ai-link-btn"
              disabled={loading || picks.length === 0}
              onClick={() => setSelectedIdsCap(pickPriorityCveIds(cves, MAX_CVE_IDS_PER_REQUEST))}
            >
              Top priority
            </button>
            <button
              type="button"
              className="ask-ai-link-btn"
              disabled={loading || !kevAvailable}
              onClick={() => setSelectedIdsCap(pickKevCveIds(cves, MAX_CVE_IDS_PER_REQUEST))}
            >
              Known exploited
            </button>
            {selectedIds.length > 0 && (
              <button
                type="button"
                className="ask-ai-link-btn"
                disabled={loading}
                onClick={() => setSelectedIdsCap([])}
              >
                Clear selection
              </button>
            )}
          </div>
          <div className="ask-ai-picks" role="group" aria-label="Toggle findings">
            {picks.length === 0 ? (
              <p className="ask-ai-picks__empty">No findings loaded</p>
            ) : (
              picks.map((id) => {
                const on = selectedIds.includes(id);
                return (
                  <button
                    key={id}
                    type="button"
                    className={`ask-ai-pick${on ? " ask-ai-pick--on" : ""}`}
                    disabled={loading || (!on && selectedIds.length >= MAX_CVE_IDS_PER_REQUEST)}
                    onClick={() => toggleCveId(id)}
                    aria-pressed={on}
                  >
                    {id}
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="ask-ai-footer__block">
          <span className="ask-ai-footer__label">Analysis</span>
          <div className="ask-ai-segments" role="radiogroup" aria-label="Analysis type">
            {ANALYZE_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                role="radio"
                aria-checked={intent === preset.id}
                className={`ask-ai-segment${intent === preset.id ? " ask-ai-segment--on" : ""}`}
                disabled={loading}
                title={preset.hint}
                onClick={() => setIntent(preset.id)}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <p className="ask-ai-footer__hint">
            {ANALYZE_PRESETS.find((p) => p.id === intent)?.hint}
          </p>
        </div>

        <button
          type="button"
          className="ask-ai-run"
          disabled={!canRun}
          onClick={run}
        >
          {loading ? "Running…" : "Run analysis"}
        </button>
      </footer>
    </section>
  );
}
