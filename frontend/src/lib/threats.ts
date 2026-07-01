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

export const THREAT_DESCRIPTION: Record<ThreatType, string> = {
  "remote-code-execution":
    "Attackers may run their own code on affected systems — the highest-impact class of vulnerability. This often leads to full system compromise without user interaction.",
  authentication:
    "Weak or broken authentication lets attackers sign in as someone else, escalate privileges, or bypass access controls entirely.",
  injection:
    "Untrusted input is interpreted as commands or queries. Attackers can read, modify, or delete data and sometimes execute code on the server.",
  "denial-of-service":
    "A flaw that can crash services, exhaust resources, or make systems unavailable to legitimate users and customers.",
  "cross-site":
    "Web-facing issues where malicious scripts or requests abuse a user's browser session to tamper with pages or steal data.",
  "information-disclosure":
    "Sensitive data — configs, credentials, internal paths, or customer data — can be read by unauthorized parties.",
  cryptographic:
    "Weak, missing, or mis-implemented encryption and TLS exposes traffic or secrets to interception and downgrade attacks.",
  misconfiguration:
    "Services left exposed, default credentials, verbose banners, or unsafe defaults widen your attack surface without a traditional software bug.",
};

export const THREAT_IMPACT: Record<ThreatType, string> = {
  "remote-code-execution": "Potential full asset takeover, lateral movement, and data exfiltration.",
  authentication: "Unauthorized access to admin panels, APIs, and sensitive business systems.",
  injection: "Database leaks, file system access, and chained exploitation into deeper networks.",
  "denial-of-service": "Outages, SLA breaches, and recovery costs during incident response.",
  "cross-site": "Session hijacking, account takeover, and defacement of customer-facing apps.",
  "information-disclosure": "Leakage of intellectual property, PII, or credentials used in follow-on attacks.",
  cryptographic: "Man-in-the-middle exposure and compliance failures for data in transit.",
  misconfiguration: "Unnecessary internet exposure and easy entry points for opportunistic scanners.",
};

export const THREAT_REMEDIATION: Record<ThreatType, string> = {
  "remote-code-execution": "Patch immediately, restrict network access to affected services, and verify no signs of exploitation.",
  authentication: "Enforce MFA, rotate credentials, review session handling, and patch auth-related CVEs.",
  injection: "Apply vendor patches, validate and sanitize inputs, and use parameterized queries where applicable.",
  "denial-of-service": "Patch or mitigate with rate limiting, WAF rules, and upstream DDoS protection.",
  "cross-site": "Update frameworks, enable CSP headers, and encode output in web applications.",
  "information-disclosure": "Patch, remove sensitive data from responses, and restrict service banners.",
  cryptographic: "Upgrade TLS versions and ciphers, rotate certificates, and disable legacy protocols.",
  misconfiguration: "Close unnecessary ports, harden defaults, and align with baseline configuration standards.",
};

export function isThreatType(value: string): value is ThreatType {
  return THREAT_ORDER.includes(value as ThreatType);
}
