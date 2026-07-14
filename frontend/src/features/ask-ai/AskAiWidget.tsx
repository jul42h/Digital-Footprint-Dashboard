import { useEffect, useRef, type FormEvent, type KeyboardEvent } from "react";
import { ChatMessageBubble, TypingIndicator } from "./ChatMessage";
import { QuickActions } from "./QuickActions";
import { useAskAiUi } from "./AskAiContext";
import { useAskAiChat } from "./useAskAiChat";

export function AskAiWidget() {
  const { open, setOpen, pendingPrompt, consumePendingPrompt } = useAskAiUi();
  const { messages, input, setInput, loading, error, send, clearChat } = useAskAiChat();
  const scrollerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const sendRef = useRef(send);
  sendRef.current = send;

  useEffect(() => {
    if (!open || !pendingPrompt) return;
    const prompt = consumePendingPrompt();
    if (prompt) void sendRef.current(prompt);
  }, [open, pendingPrompt, consumePendingPrompt]);

  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => inputRef.current?.focus(), 80);
    return () => window.clearTimeout(id);
  }, [open]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, loading, open]);

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    void send(input);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void send(input);
    }
  };

  return (
    <div className={`ask-ai-widget${open ? " ask-ai-widget--open" : ""}`}>
      {open && (
        <section
          className="ask-ai-panel"
          role="dialog"
          aria-modal="false"
          aria-label="Ask AI cybersecurity assistant"
        >
          <header className="ask-ai-panel__header">
            <div>
              <p className="ask-ai-panel__title">Ask AI</p>
              <p className="ask-ai-panel__subtitle">Cybersecurity analyst</p>
            </div>
            <div className="ask-ai-panel__header-actions">
              <button
                type="button"
                className="ask-ai-panel__ghost"
                onClick={clearChat}
                disabled={loading || messages.length === 0}
              >
                Clear
              </button>
              <button
                type="button"
                className="ask-ai-panel__ghost"
                onClick={() => setOpen(false)}
                aria-label="Close Ask AI"
              >
                ✕
              </button>
            </div>
          </header>

          <div className="ask-ai-panel__messages" ref={scrollerRef}>
            {messages.length === 0 && !loading ? (
              <div className="ask-ai-empty ask-ai-empty--compact">
                <p>Ask what to patch first, which hosts are riskiest, or why the score is high.</p>
              </div>
            ) : (
              messages.map((msg) => (
                <ChatMessageBubble key={msg.id} message={msg} compact />
              ))
            )}
            {loading && <TypingIndicator />}
          </div>

          {error && <p className="ask-ai-error">{error}</p>}

          <QuickActions compact disabled={loading} onSelect={(prompt) => void send(prompt)} />

          <form className="ask-ai-composer ask-ai-composer--compact" onSubmit={onSubmit}>
            <textarea
              ref={inputRef}
              className="ask-ai-composer__input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Ask about risks, hosts, or patches…"
              rows={1}
              disabled={loading}
              aria-label="Ask AI question"
            />
            <button
              type="submit"
              className="btn btn--primary ask-ai-composer__send"
              disabled={loading || !input.trim()}
            >
              {loading ? "…" : "Send"}
            </button>
          </form>
        </section>
      )}

      <button
        type="button"
        className={`ask-ai-fab${open ? " ask-ai-fab--active" : ""}`}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={open ? "Close Ask AI" : "Open Ask AI"}
        title="Ask AI"
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
            <span className="ask-ai-fab__label">Ask AI</span>
          </>
        )}
      </button>
    </div>
  );
}
