import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { sanitizeAiText } from "./sanitizeAiText";
import type { AnalysisIntent, ChatMessage as ChatMessageType } from "./types";
import { INTENT_USER_LABEL } from "./types";

const CVE_PREVIEW_COUNT = 2;

function RelatedCves({ ids }: { ids: string[] }) {
  const [expanded, setExpanded] = useState(false);
  if (!ids.length) return null;

  if (ids.length === 1) {
    return (
      <div className="ask-ai-msg__cves">
        <Link to={`/cves/${ids[0]}`} className="ask-ai-chip">
          {ids[0]}
        </Link>
      </div>
    );
  }

  const visible = expanded ? ids : ids.slice(0, CVE_PREVIEW_COUNT);
  const hidden = ids.length - visible.length;

  return (
    <div className="ask-ai-msg__cves">
      <span className="ask-ai-msg__cves-label">
        {ids.length} related finding{ids.length === 1 ? "" : "s"}
      </span>
      {visible.map((id) => (
        <Link key={id} to={`/cves/${id}`} className="ask-ai-chip">
          {id}
        </Link>
      ))}
      {hidden > 0 && (
        <button
          type="button"
          className="ask-ai-chip ask-ai-chip--more"
          onClick={() => setExpanded(true)}
        >
          +{hidden} more
        </button>
      )}
      {expanded && ids.length > CVE_PREVIEW_COUNT && (
        <button
          type="button"
          className="ask-ai-chip ask-ai-chip--more"
          onClick={() => setExpanded(false)}
        >
          Show less
        </button>
      )}
    </div>
  );
}

function renderInline(text: string): ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|CVE-\d{4}-\d{4,7})/gi);
  return parts.filter(Boolean).map((part, i) => {
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
    if (/^CVE-\d{4}-\d{4,7}$/i.test(part)) {
      const id = part.toUpperCase();
      return (
        <Link key={i} to={`/cves/${id}`} className="ask-ai-cve-link">
          {id}
        </Link>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

export type Section = { title: string | null; body: string };

export function splitIntoSections(content: string): Section[] {
  const cleaned = sanitizeAiText(content);
  if (!cleaned) return [];

  const lines = cleaned.split("\n");
  const sections: Section[] = [];
  let title: string | null = null;
  let buf: string[] = [];

  const flush = () => {
    const body = buf.join("\n").trim();
    if (!title && !body) return;
    sections.push({ title, body });
    title = null;
    buf = [];
  };

  for (const line of lines) {
    const heading =
      line.match(/^\s*#{1,4}\s+(.+?)\s*$/) || line.match(/^\s*\*\*(.+?)\*\*\s*$/);
    if (heading) {
      flush();
      title = heading[1].replace(/\*\*/g, "").trim();
      continue;
    }
    buf.push(line);
  }
  flush();

  return sections.filter((s) => s.title || s.body);
}

function renderBlocks(text: string): ReactNode[] {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let para: string[] = [];
  let listItems: string[] = [];

  const flushPara = () => {
    if (!para.length) return;
    blocks.push(
      <p key={`p-${blocks.length}`} className="ask-ai-msg__para">
        {renderInline(para.join(" "))}
      </p>,
    );
    para = [];
  };

  const flushList = () => {
    if (!listItems.length) return;
    blocks.push(
      <ul key={`l-${blocks.length}`} className="ask-ai-msg__list">
        {listItems.map((item, i) => (
          <li key={i}>{renderInline(item)}</li>
        ))}
      </ul>,
    );
    listItems = [];
  };

  for (const line of lines) {
    const item = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
    if (item) {
      flushPara();
      listItems.push(item[1]);
      continue;
    }
    flushList();
    if (!line.trim()) {
      flushPara();
      continue;
    }
    para.push(line.trim());
  }
  flushList();
  flushPara();
  return blocks;
}

export function ChatMessageBubble({ message }: { message: ChatMessageType }) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === "user";
  const displayContent = useMemo(
    () => (isUser ? message.content : sanitizeAiText(message.content)),
    [isUser, message.content],
  );
  const sections = useMemo(
    () => (isUser ? [] : splitIntoSections(displayContent)),
    [isUser, displayContent],
  );

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(displayContent || message.content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* ignore */
    }
  };

  const intent = message.intent
    ? INTENT_USER_LABEL[message.intent as AnalysisIntent] ?? null
    : null;

  return (
    <article
      className={`ask-ai-msg ask-ai-msg--${message.role}`}
      aria-label={isUser ? "Your request" : "AI response"}
    >
      {isUser ? (
        <div className="ask-ai-msg__user">
          <span className="ask-ai-msg__user-intent">{message.content}</span>
          {message.cveIds && message.cveIds.length > 0 && (
            <span className="ask-ai-msg__user-count">
              {message.cveIds.length} finding{message.cveIds.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
      ) : (
        <div className="ask-ai-msg__assistant">
          {intent && <p className="ask-ai-msg__intent">{intent}</p>}
          <div className="ask-ai-msg__content">
            {sections.length === 0 ? (
              <p className="ask-ai-msg__para">{displayContent}</p>
            ) : (
              sections.map((section, i) => (
                <section key={`${section.title ?? "body"}-${i}`} className="ask-ai-section">
                  {section.title && <h3 className="ask-ai-msg__heading">{section.title}</h3>}
                  {section.body && renderBlocks(section.body)}
                </section>
              ))
            )}
          </div>
          {message.cveIds && message.cveIds.length > 0 && (
            <RelatedCves ids={message.cveIds} />
          )}
          <button type="button" className="ask-ai-msg__copy" onClick={() => void copy()}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}
    </article>
  );
}

export function TypingIndicator() {
  return (
    <div className="ask-ai-msg ask-ai-msg--assistant" aria-live="polite">
      <div className="ask-ai-typing" aria-label="Working">
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}
