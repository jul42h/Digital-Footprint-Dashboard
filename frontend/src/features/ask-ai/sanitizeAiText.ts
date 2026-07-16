/**
 * Presentation cleaner for AI text in the UI.
 * The Lambda already sanitizes model output; this only strips leftover artifacts
 * so analysts never see raw model noise. It does not rewrite meaning.
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
/** Shown in place of the Lambda's raw truncation marker — deleting it silently
 * hid from analysts that a response (e.g. a remediation plan) was cut short. */
const TRUNCATION_NOTICE = "\n\n⚠ This response was cut short by the model's length limit — some content may be missing.";
/** Zero-width / BOM / bidi control junk models sometimes leak. */
const INVISIBLE_RE = /[\u200B-\u200D\uFEFF\u2060\u202A-\u202E\u2066-\u2069]/g;
/** Runs of decorative separators that add no meaning. */
const SEPARATOR_RUN_RE = /(?:^|\n)\s*([-=_*~.]{3,})\s*(?=\n|$)/g;
/** Odd leftover escape sequences from JSON/harmony leakage. */
const ESCAPED_NOISE_RE = /\\[nrt]|\\u[0-9a-fA-F]{4}/g;

export function sanitizeAiText(raw: string | null | undefined): string {
  if (!raw) return "";

  let text = raw.replace(/\r\n/g, "\n");
  text = text.replace(INVISIBLE_RE, "");

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
  // `.match()`, not `.test()`, on this shared `g`-flagged constant — `.test()`
  // would mutate its `lastIndex` and corrupt the next call to this function.
  const wasTruncated = text.match(BOILERPLATE_RE) !== null;
  text = text.replace(BOILERPLATE_RE, "\n");
  text = text.replace(SEPARATOR_RUN_RE, "\n");
  // Only collapse obvious double-escaped noise; leave normal backslashes alone.
  if (/\\[nrt]/.test(text) && !text.includes("\n\n")) {
    text = text.replace(/\\n/g, "\n").replace(/\\t/g, " ").replace(/\\r/g, "");
  }
  text = text.replace(ESCAPED_NOISE_RE, (m) => {
    if (m === "\\n") return "\n";
    if (m === "\\t" || m === "\\r") return " ";
    return "";
  });

  text = text
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, "").replace(/[ \t]{2,}/g, " "))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (wasTruncated && text) text += TRUNCATION_NOTICE;

  return text;
}
