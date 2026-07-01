import type { ThreatType } from "@/types";

/* Threat categories with plain-language labels for business readers
   and technical names for security practitioners. */

export const THREAT_ORDER: ThreatType[] = [
  "remote-code-execution",
  "authentication",
  "injection",
  "denial-of-service",
  "cross-site",
  "information-disclosure",
  "cryptographic",
  "misconfiguration",
];

export const THREAT_LABEL: Record<ThreatType, string> = {
  "remote-code-execution": "Remote takeover",
  authentication: "Access bypass",
  injection: "Data injection",
  "denial-of-service": "Service disruption",
  "cross-site": "Web tampering",
  "information-disclosure": "Data exposure",
  cryptographic: "Encryption weakness",
  misconfiguration: "Config exposure",
};

export const THREAT_TECH_LABEL: Record<ThreatType, string> = {
  "remote-code-execution": "RCE / memory corruption",
  authentication: "Auth bypass / privilege",
  injection: "SQLi / path traversal",
  "denial-of-service": "DoS / resource exhaustion",
  "cross-site": "XSS / client-side",
  "information-disclosure": "Info disclosure",
  cryptographic: "TLS / crypto flaws",
  misconfiguration: "Misconfiguration / exposure",
};

export const THREAT_COLOR: Record<ThreatType, string> = {
  "remote-code-execution": "#e0463f",
  authentication: "#e2742a",
  injection: "#b84fd4",
  "denial-of-service": "#d9a21b",
  "cross-site": "#3b8fd6",
  "information-disclosure": "#5a9e6f",
  cryptographic: "#5a7fd4",
  misconfiguration: "#8a92a0",
};
