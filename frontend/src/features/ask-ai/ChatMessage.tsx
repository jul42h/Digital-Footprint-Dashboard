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
      aria-label={isUser ? "Your message" : "AI analysis"}
    >
      <div className="ask-ai-msg__body">
        {message.cveIds && message.cveIds.length > 0 && (
          <div className="ask-ai-msg__cves">
            {message.cveIds.map((id) => (
              <Link key={id} to={`/cves/${id}`} className="ask-ai-chip">
                {id}
              </Link>
            ))}
          </div>
        )}
        <div className="ask-ai-msg__content">
          {message.content.split("\n").map((line, idx) => (
            <p key={idx} className={line.trim() ? undefined : "ask-ai-msg__break"}>
              {line.trim() ? renderInline(line) : "\u00A0"}
            </p>
          ))}
        </div>

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
        <div className="ask-ai-typing" aria-label="Generating analysis">
          <span />
          <span />
          <span />
        </div>
      </div>
    </div>
  );
}
