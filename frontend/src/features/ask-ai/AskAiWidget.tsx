import { useEffect, useRef, type FormEvent, type KeyboardEvent } from "react";
import { AnalyzeFabHint } from "@/features/onboarding/AnalyzeFabHint";
import { useCves } from "@/features/cves/hooks";
import { ChatMessageBubble, TypingIndicator } from "./ChatMessage";
import { CveQuickPicks } from "./QuickActions";
import { useAskAiUi } from "./AskAiContext";
import { useCveAnalysisChat } from "./useAskAiChat";
import { MAX_CVE_IDS_PER_REQUEST } from "./types";
import { normalizeCveId, pickKevCveIds, pickPriorityCveIds } from "./cveSelection";

export function AskAiWidget() {
  const { open, setOpen, pendingCveIds, consumePendingCveIds } = useAskAiUi();
  const cves = useCves();
  const {
    messages,
    selectedIds,
    input,
    setInput,
    loading,
    error,
    analyze,
    clearChat,
    addCveId,
    removeCveId,
    setPendingIds,
  } = useCveAnalysisChat();
  const scrollerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const analyzeRef = useRef(analyze);
  analyzeRef.current = analyze;

  useEffect(() => {
    if (!open || !pendingCveIds) return;
    const ids = consumePendingCveIds();
    if (!ids?.length) return;
    setPendingIds(ids);
    void analyzeRef.current(ids, "detail");
  }, [open, pendingCveIds, consumePendingCveIds, setPendingIds]);

  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => inputRef.current?.focus(), 80);
    return () => window.clearTimeout(id);
  }, [open]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, loading, open]);

  const commitInput = () => {
    const parts = input.split(/[\s,]+/).filter(Boolean);
    let added = false;
    for (const part of parts) {
      if (addCveId(part)) added = true;
    }
    if (added) setInput("");
  };

  const fillIds = (ids: string[]) => {
    setPendingIds(ids.slice(0, MAX_CVE_IDS_PER_REQUEST));
  };

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    commitInput();
    void analyze(undefined, "detail");
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      const id = normalizeCveId(input);
      if (id) {
        addCveId(id);
        setInput("");
        return;
      }
      void analyze(undefined, "detail");
    }
  };

  const togglePick = (cveId: string) => {
    if (selectedIds.includes(cveId)) removeCveId(cveId);
    else addCveId(cveId);
  };

  return (
    <div className={`ask-ai-widget${open ? " ask-ai-widget--open" : ""}`}>
      <AnalyzeFabHint panelOpen={open} />

      {open && (
        <section
          className="ask-ai-panel"
          role="dialog"
          aria-modal="false"
          aria-label="CVE risk analysis"
        >
          <header className="ask-ai-panel__header">
            <div>
              <p className="ask-ai-panel__title">Risk analysis</p>
              <p className="ask-ai-panel__subtitle">
                Up to {MAX_CVE_IDS_PER_REQUEST} CVEs · deeper write-up than the home brief
              </p>
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
              <button
                type="button"
                className="ask-ai-panel__ghost"
                onClick={() => setOpen(false)}
                aria-label="Close risk analysis"
              >
                ✕
              </button>
            </div>
          </header>

          <div className="ask-ai-panel__messages" ref={scrollerRef}>
            {messages.length === 0 && !loading ? (
              <div className="ask-ai-empty ask-ai-empty--compact">
                <p>
                  Select findings, then Analyze for exploitability, impact, and remediation order.
                  For a short scan-ready summary, use <strong>Generate brief</strong> on Home.
                </p>
                <div className="ask-ai-presets" role="group" aria-label="Quick fill">
                  <button
                    type="button"
                    className="ask-ai-presets__btn"
                    disabled={loading || cves.length === 0}
                    onClick={() => fillIds(pickPriorityCveIds(cves, MAX_CVE_IDS_PER_REQUEST))}
                  >
                    Fill priority
                  </button>
                  <button
                    type="button"
                    className="ask-ai-presets__btn"
                    disabled={loading || pickKevCveIds(cves, 1).length === 0}
                    onClick={() => fillIds(pickKevCveIds(cves, MAX_CVE_IDS_PER_REQUEST))}
                  >
                    Fill KEV
                  </button>
                </div>
              </div>
            ) : (
              messages.map((msg) => <ChatMessageBubble key={msg.id} message={msg} compact />)
            )}
            {loading && <TypingIndicator />}
          </div>

          {error && <p className="ask-ai-error">{error}</p>}

          {selectedIds.length > 0 && (
            <div className="ask-ai-selected" aria-label="Selected CVE IDs">
              {selectedIds.map((id) => (
                <button
                  key={id}
                  type="button"
                  className="ask-ai-selected__chip"
                  onClick={() => removeCveId(id)}
                  disabled={loading}
                  title="Remove"
                >
                  {id} <span aria-hidden>×</span>
                </button>
              ))}
            </div>
          )}

          <CveQuickPicks disabled={loading} selectedIds={selectedIds} onToggle={togglePick} />

          <form className="ask-ai-composer ask-ai-composer--compact" onSubmit={onSubmit}>
            <input
              ref={inputRef}
              className="ask-ai-composer__input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              onBlur={commitInput}
              placeholder="Add CVE-YYYY-NNNN"
              disabled={loading || selectedIds.length >= MAX_CVE_IDS_PER_REQUEST}
              aria-label="CVE ID to analyze"
            />
            <button
              type="submit"
              className="btn btn--primary ask-ai-composer__send"
              disabled={loading || (selectedIds.length === 0 && !normalizeCveId(input))}
            >
              {loading ? "…" : "Analyze"}
            </button>
          </form>
        </section>
      )}

      <button
        type="button"
        className={`ask-ai-fab${open ? " ask-ai-fab--active" : ""}`}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={open ? "Close risk analysis" : "Open risk analysis"}
        title="Risk analysis"
      >
        {open ? (
          <span aria-hidden>✕</span>
        ) : (
          <>
            <span className="ask-ai-fab__icon" aria-hidden>
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.75">
                <path
                  d="M5 6.5A2.5 2.5 0 017.5 4h9A2.5 2.5 0 0119 6.5v6A2.5 2.5 0 0116.5 15H11l-3.5 3v-3H7.5A2.5 2.5 0 015 12.5v-6z"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            <span className="ask-ai-fab__label">Analyze</span>
          </>
        )}
      </button>
    </div>
  );
}
