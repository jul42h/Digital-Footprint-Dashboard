import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { useDashboard } from "@/context/DashboardContext";
import { peekCachedAnalysis } from "@/features/ask-ai/askAiApi";
import { DEFAULT_PRIORITY_COUNT, pickPriorityCves } from "@/features/ask-ai/cveSelection";
import { toAnalysisFindingsFromData } from "@/features/ask-ai/findings";
import { useCves } from "@/features/cves/hooks";
import { ChatMessageBubble, TypingIndicator } from "./ChatMessage";
import { useAskAiUi } from "./AskAiContext";
import { useCveAnalysisChat } from "./useAskAiChat";
import { normalizeCveId, pickKevCveIds, pickPriorityCveIds } from "./cveSelection";
import {
  GUIDED_QUESTION_GROUPS,
  pickFollowUpActions,
  type FollowUpAction,
} from "./guidedQuestions";
import {
  MAX_CVE_IDS_PER_REQUEST,
  MAX_FINDINGS_PER_REQUEST,
  MAX_QUESTION_LENGTH,
  QUESTION_SOFT_LIMIT,
} from "./types";

const QUICK_QUESTIONS = GUIDED_QUESTION_GROUPS.flatMap((group) => group.items).filter((item) =>
  ["fix-first", "risk-score-drivers", "active-exploitation"].includes(item.id),
);

const CVE_MENTION_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const CVE_ONLY_LIKE_RE = /^CVE(?:[-\s]\d[\dA-Z-\s]*)?$/i;

function DashboardContextStrip() {
  const { data: dashboard } = useDashboard();
  const cves = useCves();

  const context = useMemo(() => {
    const focus = pickPriorityCves(cves, DEFAULT_PRIORITY_COUNT);
    const focusIds = focus.map((c) => c.id.toUpperCase());
    const findings = toAnalysisFindingsFromData(dashboard, {
      preferCveIds: focusIds,
      limit: MAX_FINDINGS_PER_REQUEST,
    });
    const brief = focusIds.length
      ? peekCachedAnalysis(focusIds, "brief", findings)
      : null;
    const risk = brief?.risk_score;
    const analyzed =
      brief?.total_findings_analyzed ??
      brief?.signal_summary?.findings_analyzed ??
      findings.length;
    const parts: string[] = [];
    if (analyzed > 0) {
      parts.push(`${analyzed} finding${analyzed === 1 ? "" : "s"} loaded`);
    }
    if (risk) {
      parts.push(`Risk score ${risk.score} (${risk.rating})`);
    }
    return parts.join(" · ");
  }, [cves, dashboard]);

  if (!context) return null;
  return <p className="ask-ai-panel__context">{context}</p>;
}

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
        aria-label={open ? "Close Ask AI" : "Open Ask AI"}
        title="Ask AI"
      >
        {open ? (
          <span aria-hidden>✕</span>
        ) : (
          <>
            <AnalyzeIcon />
            <span className="ask-ai-fab__label">Ask AI</span>
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
    ask,
    lookupCve,
    clearChat,
    toggleCveId,
    setSelectedIdsCap,
  } = useCveAnalysisChat();

  const [question, setQuestion] = useState("");
  const [findingsOpen, setFindingsOpen] = useState(false);
  const [examplesOpen, setExamplesOpen] = useState(false);
  const scrollerRef = useRef<HTMLDivElement>(null);
  const examplesRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!pendingCveIds?.length) return;
    const ids = consumePendingCveIds();
    if (!ids?.length) return;
    setSelectedIdsCap(ids);
    setFindingsOpen(true);
  }, [pendingCveIds, consumePendingCveIds, setSelectedIdsCap]);

  const picks = useMemo(() => {
    const priority = pickPriorityCveIds(cves, MAX_CVE_IDS_PER_REQUEST);
    const extras = selectedIds.filter((id) => !priority.includes(id));
    return [...extras, ...priority].slice(0, MAX_CVE_IDS_PER_REQUEST + extras.length);
  }, [cves, selectedIds]);

  const kevAvailable = pickKevCveIds(cves, 1).length > 0;
  const canRemediate = selectedIds.length > 0 && !loading;
  const questionLen = question.length;
  const nearLimit = questionLen >= QUESTION_SOFT_LIMIT;
  const directCveLookup =
    normalizeCveId(question) !== null || CVE_ONLY_LIKE_RE.test(question.trim());

  const followUps = useMemo(() => {
    if (loading || messages.length === 0) return [];
    const last = messages[messages.length - 1];
    if (last.role !== "assistant") return [];
    const priorUser = [...messages].reverse().find((m) => m.role === "user");
    return pickFollowUpActions({
      lastUserContent: priorUser?.content,
      cveIds: last.cveIds ?? priorUser?.cveIds,
      intent: last.intent,
      limit: 3,
    });
  }, [loading, messages]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, loading, followUps]);

  useEffect(() => {
    if (!examplesOpen) return;
    const onPointerDown = (event: MouseEvent) => {
      const root = examplesRef.current;
      if (root && !root.contains(event.target as Node)) {
        setExamplesOpen(false);
      }
    };
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setExamplesOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [examplesOpen]);

  const runExample = (item: { id: string; label: string }) => {
    setExamplesOpen(false);
    void ask("", {
      questionId: item.id,
      displayLabel: item.label,
    });
  };

  const runFollowUp = (item: FollowUpAction) => {
    if (loading) return;
    if (item.kind === "remediate") {
      const ids = item.cveIds?.length ? item.cveIds : selectedIds;
      if (!ids.length) {
        setFindingsOpen(true);
        return;
      }
      setSelectedIdsCap(ids);
      void analyze(ids, "remediate");
      return;
    }
    void ask("", {
      questionId: item.questionId,
      questionParams: item.params,
      displayLabel: item.label,
      focusCveIds: item.params?.cve_id ? [item.params.cve_id] : undefined,
    });
  };

  const clearConversation = () => {
    clearChat();
    setQuestion("");
    setFindingsOpen(false);
    setExamplesOpen(false);
  };

  const submitQuestion = (event: FormEvent) => {
    event.preventDefault();
    const value = question.trim().slice(0, MAX_QUESTION_LENGTH);
    if (!value || loading) return;
    setQuestion("");
    setExamplesOpen(false);

    const exactCve = normalizeCveId(value);
    if (exactCve || CVE_ONLY_LIKE_RE.test(value)) {
      void lookupCve(value);
      return;
    }

    const mentionedCveIds = [
      ...new Set((value.match(CVE_MENTION_RE) ?? []).map((id) => id.toUpperCase())),
    ].slice(0, MAX_CVE_IDS_PER_REQUEST);
    const focusCveIds = mentionedCveIds.length
      ? mentionedCveIds
      : selectedIds.length
        ? selectedIds
        : undefined;
    void ask(value, { focusCveIds });
  };

  const onComposerKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      submitQuestion(event);
    }
  };

  return (
    <section className="ask-ai-panel" role="dialog" aria-label="Ask AI">
      <header className="ask-ai-panel__header">
        <div>
          <h2 className="ask-ai-panel__title">Ask AI</h2>
          <p className="ask-ai-panel__sub">Ask questions or build a remediation plan</p>
          <DashboardContextStrip />
        </div>
        <div className="ask-ai-panel__header-actions">
          <button
            type="button"
            className="ask-ai-panel__ghost"
            onClick={clearConversation}
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
            <span className="ask-ai-empty__mark" aria-hidden>
              AI
            </span>
            <p className="ask-ai-empty__title">What do you need?</p>
            <p className="ask-ai-empty__hint">
              Ask a question, enter a CVE ID, or browse Examples below.
            </p>
            <div className="ask-ai-quick-list" role="group" aria-label="Suggested questions">
              {QUICK_QUESTIONS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="ask-ai-quick-btn"
                  disabled={loading}
                  onClick={() =>
                    void ask("", {
                      questionId: item.id,
                      displayLabel: item.label,
                    })
                  }
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg) => <ChatMessageBubble key={msg.id} message={msg} />)
        )}
        {loading && <TypingIndicator />}
        {followUps.length > 0 && (
          <div className="ask-ai-followups" role="group" aria-label="Suggested next steps">
            <span className="ask-ai-followups__label">Next steps</span>
            <div className="ask-ai-followups__list">
              {followUps.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="ask-ai-followups__btn"
                  disabled={loading}
                  onClick={() => runFollowUp(item)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {error && !loading && <p className="ask-ai-error">{error}</p>}

      <footer className="ask-ai-panel__footer">
        <details
          className="ask-ai-findings"
          open={findingsOpen}
          onToggle={(e) => setFindingsOpen((e.target as HTMLDetailsElement).open)}
        >
          <summary className="ask-ai-findings__summary">
            <span className="ask-ai-findings__title">Findings for remediation</span>
            <span className="ask-ai-footer__meta">
              {selectedIds.length}/{MAX_CVE_IDS_PER_REQUEST}
            </span>
          </summary>
          <div className="ask-ai-findings__body">
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
                  Clear
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
        </details>

        <div className="ask-ai-composer-wrap" ref={examplesRef}>
          {examplesOpen && (
            <div
              id="ask-ai-examples-panel"
              className="ask-ai-examples"
              role="dialog"
              aria-label="In-scope example questions"
            >
              <p className="ask-ai-examples__intro">
                Questions grounded in this footprint’s findings and risk data.
              </p>
              {GUIDED_QUESTION_GROUPS.map((group) => (
                <div key={group.id} className="ask-ai-examples__group">
                  <span className="ask-ai-examples__group-label">{group.label}</span>
                  <div className="ask-ai-examples__list">
                    {group.items.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        className="ask-ai-examples__btn"
                        disabled={loading}
                        onClick={() => runExample(item)}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
              <p className="ask-ai-examples__tips">
                You can also enter a CVE ID, or select findings and choose Remediate.
              </p>
            </div>
          )}

          <form className="ask-ai-composer" onSubmit={submitQuestion}>
            <textarea
              className="ask-ai-composer__input"
              rows={2}
              autoComplete="off"
              maxLength={MAX_QUESTION_LENGTH}
              placeholder="Ask about risk, assets, or enter a CVE ID…"
              aria-label="Ask AI a question or enter a CVE ID"
              value={question}
              disabled={loading}
              onChange={(e) => setQuestion(e.target.value.slice(0, MAX_QUESTION_LENGTH))}
              onKeyDown={onComposerKeyDown}
            />
            <div className="ask-ai-composer__bar">
              <button
                type="button"
                className={`ask-ai-examples-toggle${examplesOpen ? " ask-ai-examples-toggle--on" : ""}`}
                aria-expanded={examplesOpen}
                aria-controls="ask-ai-examples-panel"
                title="Browse in-scope example questions"
                disabled={loading}
                onClick={() => setExamplesOpen((open) => !open)}
              >
                Examples
              </button>
              <span
                className={`ask-ai-composer__count${nearLimit ? " ask-ai-composer__count--warn" : ""}`}
                aria-live="polite"
              >
                {nearLimit ? `${questionLen}/${MAX_QUESTION_LENGTH}` : ""}
              </span>
              <div className="ask-ai-composer__actions">
                <button
                  type="button"
                  className="ask-ai-run ask-ai-run--secondary"
                  disabled={!canRemediate}
                  onClick={() => void analyze(selectedIds, "remediate")}
                >
                  {loading ? "Running…" : "Remediate"}
                </button>
                <button
                  type="submit"
                  className="ask-ai-send"
                  disabled={loading || !question.trim()}
                >
                  {loading ? "…" : directCveLookup ? "Look up" : "Ask"}
                </button>
              </div>
            </div>
          </form>
        </div>
      </footer>
    </section>
  );
}
