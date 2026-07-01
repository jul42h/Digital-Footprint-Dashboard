import type { Severity } from "@/types";

/* Single source of truth for severity. Every panel imports from here so
   the CVSS color scale never drifts between the table, the trend, and
   the breakdown. */

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

/* Standard CVSS v3 severity bands. */
export function cvssToSeverity(cvss: number): Severity {
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

/* Charts need real color values, not CSS var names. Reads the computed
   custom properties so they stay in sync with the stylesheet + theme. */
export function severityColorValue(severity: Severity): string {
  if (typeof window === "undefined") return "#888";
  return getComputedStyle(document.documentElement)
    .getPropertyValue(`--sev-${severity}`)
    .trim();
}
