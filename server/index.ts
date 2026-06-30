import express from 'express';
import cors from 'cors';
import { fetchRecentCVEs } from './nvd.js';
import { fetchIPIntelligence } from './ipIntel.js';
import type { DashboardStats, ThreatEvent } from './types.js';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

let cveCache: Awaited<ReturnType<typeof fetchRecentCVEs>> = [];
let ipCache: Awaited<ReturnType<typeof fetchIPIntelligence>> = [];
let lastRefresh = 0;
const CACHE_TTL = 5 * 60 * 1000;

async function refreshData() {
  const now = Date.now();
  if (now - lastRefresh < CACHE_TTL && cveCache.length > 0) return;

  console.log('Refreshing OSINT data...');
  const [cves, ips] = await Promise.all([fetchRecentCVEs(), fetchIPIntelligence()]);
  cveCache = cves;
  ipCache = ips;
  lastRefresh = now;
  console.log(`Loaded ${cves.length} CVEs and ${ips.length} IPs`);
}

function buildStats(): DashboardStats {
  const scored = cveCache.filter((c) => c.cvssScore !== null);
  const avgCvss =
    scored.length > 0
      ? scored.reduce((sum, c) => sum + (c.cvssScore ?? 0), 0) / scored.length
      : 0;

  return {
    totalCVEs: cveCache.length,
    criticalCVEs: cveCache.filter((c) => c.severity === 'CRITICAL').length,
    highCVEs: cveCache.filter((c) => c.severity === 'HIGH').length,
    monitoredIPs: ipCache.length,
    highRiskIPs: ipCache.filter(
      (ip) => ip.threatLevel === 'critical' || ip.threatLevel === 'high',
    ).length,
    totalAffectedProducts: cveCache.reduce((sum, c) => sum + c.affectedCount, 0),
    avgCvssScore: Math.round(avgCvss * 10) / 10,
  };
}

function buildThreatFeed(): ThreatEvent[] {
  const events: ThreatEvent[] = [];

  for (const cve of cveCache.slice(0, 5)) {
    if (cve.severity === 'CRITICAL' || cve.severity === 'HIGH') {
      events.push({
        id: `cve-${cve.id}`,
        timestamp: cve.published,
        type: 'cve',
        severity: cve.severity === 'CRITICAL' ? 'critical' : 'high',
        title: `${cve.id} published`,
        detail: `${cve.affectedCount} products affected · CVSS ${cve.cvssScore ?? 'N/A'}`,
      });
    }
  }

  for (const ip of ipCache.filter(
    (i) => i.threatLevel === 'critical' || i.threatLevel === 'high',
  )) {
    events.push({
      id: `ip-${ip.ip}`,
      timestamp: ip.lastSeen,
      type: 'ip',
      severity: ip.threatLevel === 'critical' ? 'critical' : 'high',
      title: `Suspicious activity from ${ip.ip}`,
      detail: `${ip.threatTags.join(', ')} · ${ip.country}`,
    });
  }

  events.push({
    id: 'scan-1',
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    type: 'scan',
    severity: 'medium',
    title: 'Port scan detected on subnet 10.0.1.0/24',
    detail: 'Ports 22, 80, 443, 3389 probed from external source',
  });

  events.push({
    id: 'exploit-1',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    type: 'exploit',
    severity: 'critical',
    title: 'Exploit attempt blocked',
    detail: 'Log4Shell signature detected and mitigated at WAF layer',
  });

  return events
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 12);
}

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', lastRefresh });
});

app.get('/api/dashboard', async (_req, res) => {
  try {
    await refreshData();
    res.json({
      stats: buildStats(),
      cves: cveCache,
      ips: ipCache,
      threats: buildThreatFeed(),
      lastUpdated: new Date(lastRefresh).toISOString(),
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  }
});

app.get('/api/cves', async (_req, res) => {
  try {
    await refreshData();
    res.json(cveCache);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load CVEs' });
  }
});

app.get('/api/ips', async (_req, res) => {
  try {
    await refreshData();
    res.json(ipCache);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load IP intelligence' });
  }
});

app.listen(PORT, () => {
  console.log(`OSINT API server running on http://localhost:${PORT}`);
  refreshData();
});
