import type { ThreatType } from '@/types';

const RULES: Array<{ type: ThreatType; patterns: RegExp[] }> = [
  {
    type: 'remote-code-execution',
    patterns: [/remote code|rce|overflow|buffer|execute|arbitrary code/i],
  },
  {
    type: 'authentication',
    patterns: [/auth|bypass|privilege|session|credential|login/i],
  },
  {
    type: 'injection',
    patterns: [/inject|sql|traversal|path traversal|upload/i],
  },
  {
    type: 'denial-of-service',
    patterns: [/denial|dos|crash|exhaust|amplification|reset/i],
  },
  {
    type: 'cross-site',
    patterns: [/xss|cross.site|script/i],
  },
  {
    type: 'information-disclosure',
    patterns: [/disclos|expos|leak|snmp|verbose|read access/i],
  },
  {
    type: 'cryptographic',
    patterns: [/tls|ssl|crypto|cipher|downgrade/i],
  },
  {
    type: 'misconfiguration',
    patterns: [/misconfig|banner|deprecated|exposed|open ntp/i],
  },
];

export function inferThreatType(summary: string): ThreatType {
  const text = summary || '';
  for (const rule of RULES) {
    if (rule.patterns.some((p) => p.test(text))) return rule.type;
  }
  return 'information-disclosure';
}
