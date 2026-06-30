import type { IPIntel } from './types.js';

interface ThreatProfile {
  threatLevel: IPIntel['threatLevel'];
  threatTags: string[];
  ports: number[];
  lastSeenOffsetHours: number;
}

const MONITORED_IPS: Record<string, ThreatProfile> = {
  '185.220.101.1': {
    threatLevel: 'high',
    threatTags: ['Tor Exit Node', 'Anonymizer'],
    ports: [443, 9001],
    lastSeenOffsetHours: 2,
  },
  '45.155.205.233': {
    threatLevel: 'critical',
    threatTags: ['Brute Force', 'SSH Scanner', 'Known Botnet'],
    ports: [22, 23, 3389],
    lastSeenOffsetHours: 1,
  },
  '89.248.165.108': {
    threatLevel: 'high',
    threatTags: ['Mass Scanner', 'Shodan', 'Reconnaissance'],
    ports: [80, 443, 8080, 8443],
    lastSeenOffsetHours: 4,
  },
  '194.36.1.13': {
    threatLevel: 'medium',
    threatTags: ['Spam Source', 'Phishing Host'],
    ports: [25, 587],
    lastSeenOffsetHours: 8,
  },
  '103.253.145.120': {
    threatLevel: 'critical',
    threatTags: ['C2 Server', 'Malware Distribution'],
    ports: [4444, 8080, 1337],
    lastSeenOffsetHours: 0.5,
  },
  '23.129.64.130': {
    threatLevel: 'medium',
    threatTags: ['Tor Relay', 'Privacy Network'],
    ports: [9001, 9030],
    lastSeenOffsetHours: 12,
  },
  '178.128.167.58': {
    threatLevel: 'low',
    threatTags: ['Cloud Hosting', 'Legitimate Scanner'],
    ports: [22, 80, 443],
    lastSeenOffsetHours: 24,
  },
  '192.168.1.1': {
    threatLevel: 'clean',
    threatTags: ['Internal Gateway', 'Trusted'],
    ports: [80, 443],
    lastSeenOffsetHours: 0.1,
  },
};

interface IpApiResponse {
  status: string;
  country?: string;
  countryCode?: string;
  city?: string;
  isp?: string;
  org?: string;
  as?: string;
  query?: string;
}

async function enrichIP(ip: string): Promise<Partial<IPIntel>> {
  try {
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,org,as,query`,
    );
    if (!response.ok) return { ip };

    const data = (await response.json()) as IpApiResponse;
    if (data.status !== 'success') return { ip };

    return {
      ip: data.query ?? ip,
      country: data.country ?? 'Unknown',
      countryCode: data.countryCode ?? '??',
      city: data.city ?? 'Unknown',
      isp: data.isp ?? 'Unknown',
      org: data.org ?? 'Unknown',
      asn: data.as ?? 'Unknown',
    };
  } catch {
    return { ip };
  }
}

export async function fetchIPIntelligence(): Promise<IPIntel[]> {
  const results: IPIntel[] = [];

  for (const [ip, profile] of Object.entries(MONITORED_IPS)) {
    const enriched = await enrichIP(ip);
    const lastSeen = new Date(
      Date.now() - profile.lastSeenOffsetHours * 60 * 60 * 1000,
    ).toISOString();

    results.push({
      ip,
      country: enriched.country ?? 'Unknown',
      countryCode: enriched.countryCode ?? '??',
      city: enriched.city ?? 'Unknown',
      isp: enriched.isp ?? 'Unknown',
      org: enriched.org ?? 'Unknown',
      asn: enriched.asn ?? 'Unknown',
      threatLevel: profile.threatLevel,
      threatTags: profile.threatTags,
      lastSeen,
      ports: profile.ports,
    });
  }

  const threatOrder: Record<IPIntel['threatLevel'], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    clean: 4,
  };

  return results.sort(
    (a, b) => threatOrder[a.threatLevel] - threatOrder[b.threatLevel],
  );
}
