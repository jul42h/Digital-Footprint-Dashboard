import type { Severity } from "@/types";
import { SEVERITY_LABEL } from "@/lib/severity";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge badge--${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}
