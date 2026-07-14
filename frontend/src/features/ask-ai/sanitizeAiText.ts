/**
 * Defense-in-depth cleaner for AI text shown in the UI.
 * The deployed Lambda should already run `_sanitize_output`; this mirrors that
 * logic so leaked harmony / reasoning tokens never reach the screen.
 */

const HARMONY_FINAL_RE = /<\|channel\|>\s*final\s*<\|message\|>/gi;
const HARMONY_TOKEN_RE = /<\|[^|]*\|>/g;
const REASON_BLOCK_RE =
  /<\s*(think|thinking|reasoning|analysis|scratchpad)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi;
const REASON_TAG_RE =
  /<\s*\/?\s*(think|thinking|reasoning|analysis|scratchpad|final|commentary)\b[^>]*>/gi;
const FENCE_RE = /^\s*```[A-Za-z]*\s*\n([\s\S]*?)\n?\s*```\s*$/;
const HEADING_RE = /^#{1,4}\s+\S/m;
const LEAD_CHANNEL_RE = /^(assistant)?\s*(analysis|commentary|final)\b[:.\s]*/i;
const BOILERPLATE_RE =
  /(?:^|\n)\s*_?Output truncated at the token limit\.?_?\s*(?=\n|$)/gi;

export function sanitizeAiText(raw: string | null | undefined): string {
  if (!raw) return "";

  let text = raw.replace(/\r\n/g, "\n");

  const finals = [...text.matchAll(HARMONY_FINAL_RE)];
  if (finals.length) {
    const last = finals[finals.length - 1];
    text = text.slice((last.index ?? 0) + last[0].length);
  }

  text = text.replace(REASON_BLOCK_RE, "");
  text = text.replace(HARMONY_TOKEN_RE, "");
  text = text.replace(REASON_TAG_RE, "");

  const fenced = text.match(FENCE_RE);
  if (fenced) text = fenced[1];

  const heading = text.match(HEADING_RE);
  if (heading && heading.index != null && heading.index > 0) {
    text = text.slice(heading.index);
  }

  text = text.replace(LEAD_CHANNEL_RE, "");
  text = text.replace(BOILERPLATE_RE, "\n");
  text = text
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return text;
}
