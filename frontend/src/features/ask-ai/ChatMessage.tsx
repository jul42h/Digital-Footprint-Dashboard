import { useState } from "react";
import { Link } from "react-router-dom";
import type { ChatMessage as ChatMessageType } from "./types";

function renderInline(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|CVE-\d{4}-\d+)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="ask-ai-code">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (/^CVE-\d{4}-\d+$/.test(part)) {
      return (
        <Link key={i} to={`/cves/${part}`} className="ask-ai-cve-link">
          {part}
        </Link>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

export function ChatMessageBubble({
  message,
  compact = false,
}: {
  message: ChatMessageType;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === "user";
  const structured = message.structured;
  const body = structured?.summary?.trim() || message.content;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      /* ignore */
    }
  };

  return (
    <article
      className={`ask-ai-msg ask-ai-msg--${message.role}${compact ? " ask-ai-msg--compact" : ""}`}
      aria-label={isUser ? "Your message" : "Analyst response"}
    >
      {!compact && (
        <div className="ask-ai-msg__avatar" aria-hidden>
          {isUser ? "You" : "AI"}
        </div>
      )}
      <div className="ask-ai-msg__body">
        <div className="ask-ai-msg__content">
          {body.split("\n").map((line, idx) => (
            <p key={idx} className={line.trim() ? undefined : "ask-ai-msg__break"}>
              {line.trim() ? renderInline(line) : "\u00A0"}
            </p>
          ))}
        </div>

        {!isUser && structured && (
          <div className={`ask-ai-structured${compact ? " ask-ai-structured--compact" : ""}`}>
            {structured.riskScore != null && (
              <div className="ask-ai-structured__score">
                Risk <strong>{structured.riskScore}</strong>
                <span>/100</span>
              </div>
            )}
            {structured.remediation?.length > 0 && (
              <ul className="ask-ai-structured__mini">
                {structured.remediation.slice(0, compact ? 3 : 6).map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
            {structured.references?.length > 0 && (
              <div className="ask-ai-structured__refs">
                {structured.references.slice(0, compact ? 4 : 8).map((ref) =>
                  /^CVE-\d{4}-\d+$/i.test(ref) ? (
                    <Link key={ref} to={`/cves/${ref}`} className="ask-ai-chip">
                      {ref}
                    </Link>
                  ) : (
                    <span key={ref} className="ask-ai-chip">
                      {ref}
                    </span>
                  ),
                )}
              </div>
            )}
          </div>
        )}

        {!isUser && (
          <div className="ask-ai-msg__actions">
            <button type="button" className="ask-ai-icon-btn" onClick={copy}>
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        )}
      </div>
    </article>
  );
}

export function TypingIndicator() {
  return (
    <div className="ask-ai-msg ask-ai-msg--assistant ask-ai-msg--typing ask-ai-msg--compact" aria-live="polite">
      <div className="ask-ai-msg__body">
        <div className="ask-ai-typing" aria-label="Analyst is typing">
          <span />
          <span />
          <span />
        </div>
      </div>
    </div>
  );
}
