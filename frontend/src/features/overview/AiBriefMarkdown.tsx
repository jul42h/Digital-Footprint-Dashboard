import { useMemo, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { sanitizeAiText } from "@/features/ask-ai/sanitizeAiText";
import { splitIntoSections } from "@/features/ask-ai/ChatMessage";

function renderInline(text: string): ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|CVE-\d{4}-\d{4,7})/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="ai-brief-code">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (/^CVE-\d{4}-\d{4,7}$/i.test(part)) {
      const id = part.toUpperCase();
      return (
        <Link key={i} to={`/cves/${id}`} className="ai-brief-cve-link">
          {id}
        </Link>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

function renderBlocks(text: string): ReactNode[] {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let para: string[] = [];
  let listItems: string[] = [];

  const flushPara = () => {
    if (!para.length) return;
    blocks.push(
      <p key={`p-${blocks.length}`} className="ai-brief-md__para">
        {renderInline(para.join(" "))}
      </p>,
    );
    para = [];
  };

  const flushList = () => {
    if (!listItems.length) return;
    blocks.push(
      <ul key={`l-${blocks.length}`} className="ai-brief-md__list">
        {listItems.map((item, i) => (
          <li key={i}>{renderInline(item)}</li>
        ))}
      </ul>,
    );
    listItems = [];
  };

  for (const line of lines) {
    const bulleted = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
    if (bulleted) {
      flushPara();
      listItems.push(bulleted[1]);
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

/** Structured markdown brief: headings, bullets, linked CVEs — no raw hash marks. */
export function AiBriefMarkdown({
  content,
  collapsed,
  maxCollapsedSections = 1,
}: {
  content: string;
  collapsed?: boolean;
  maxCollapsedSections?: number;
}) {
  const sections = useMemo(() => {
    const cleaned = sanitizeAiText(content);
    const split = splitIntoSections(cleaned);
    if (!split.length && cleaned) {
      return [{ title: null as string | null, body: cleaned }];
    }
    return split;
  }, [content]);

  const visible = collapsed ? sections.slice(0, maxCollapsedSections) : sections;
  const hiddenCount = Math.max(0, sections.length - visible.length);

  if (!visible.length) return null;

  return (
    <div className="ai-brief-md">
      {visible.map((section, i) => (
        <section key={`${section.title ?? "body"}-${i}`} className="ai-brief-md__section">
          {section.title && <h3 className="ai-brief-md__title">{section.title}</h3>}
          <div className="ai-brief-md__body">{renderBlocks(section.body)}</div>
        </section>
      ))}
      {collapsed && hiddenCount > 0 && (
        <p className="ai-brief-md__more-hint">+{hiddenCount} more section{hiddenCount === 1 ? "" : "s"}</p>
      )}
    </div>
  );
}

export function briefHasMoreSections(content: string, maxCollapsedSections = 1): boolean {
  const cleaned = sanitizeAiText(content);
  const split = splitIntoSections(cleaned);
  const count = split.length || (cleaned ? 1 : 0);
  return count > maxCollapsedSections;
}
