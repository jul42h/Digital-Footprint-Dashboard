import type { CVEItem } from './types.js';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function severityFromScore(score: number | null): CVEItem['severity'] {
  if (score === null) return 'NONE';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

function extractCvss(cve: Record<string, unknown>): {
  score: number | null;
  vector: string | null;
  exploitability: string | null;
} {
  const metrics = cve.metrics as Record<string, unknown> | undefined;
  if (!metrics) return { score: null, vector: null, exploitability: null };

  const v31 = metrics.cvssMetricV31 as Array<Record<string, unknown>> | undefined;
  const v30 = metrics.cvssMetricV30 as Array<Record<string, unknown>> | undefined;
  const metric = v31?.[0] ?? v30?.[0];
  if (!metric) return { score: null, vector: null, exploitability: null };

  const cvssData = metric.cvssData as Record<string, unknown> | undefined;
  const score = typeof cvssData?.baseScore === 'number' ? cvssData.baseScore : null;
  const vector = typeof cvssData?.vectorString === 'string' ? cvssData.vectorString : null;
  const exploitability =
    typeof metric.exploitabilityScore === 'number'
      ? metric.exploitabilityScore.toFixed(1)
      : null;

  return { score, vector, exploitability };
}

function extractProducts(cve: Record<string, unknown>): string[] {
  const configurations = cve.configurations as Array<Record<string, unknown>> | undefined;
  if (!configurations) return [];

  const products: string[] = [];
  for (const config of configurations) {
    const nodes = config.nodes as Array<Record<string, unknown>> | undefined;
    if (!nodes) continue;
    for (const node of nodes) {
      const matches = node.cpeMatch as Array<Record<string, unknown>> | undefined;
      if (!matches) continue;
      for (const match of matches) {
        if (match.vulnerable !== true) continue;
        const criteria = match.criteria as string | undefined;
        if (!criteria) continue;
        const parts = criteria.split(':');
        if (parts.length >= 5) {
          const vendor = parts[3];
          const product = parts[4];
          if (vendor && product && vendor !== '*' && product !== '*') {
            products.push(`${vendor}:${product}`);
          }
        }
      }
    }
  }
  return [...new Set(products)];
}

function parseNvdResponse(data: Record<string, unknown>): CVEItem[] {
  const vulnerabilities = data.vulnerabilities as Array<Record<string, unknown>> | undefined;
  if (!vulnerabilities) return [];

  return vulnerabilities.map((vuln) => {
    const cve = vuln.cve as Record<string, unknown>;
    const id = cve.id as string;

    const descriptions = cve.descriptions as Array<Record<string, string>> | undefined;
    const enDesc = descriptions?.find((d) => d.lang === 'en');
    const description = enDesc?.value ?? 'No description available';

    const { score, vector, exploitability } = extractCvss(cve);
    const affectedProducts = extractProducts(cve);
    const published = (cve.published as string) ?? '';

    return {
      id,
      description,
      cvssScore: score,
      severity: severityFromScore(score),
      published,
      affectedProducts,
      affectedCount: affectedProducts.length,
      exploitability,
      vector,
    };
  });
}

export async function fetchRecentCVEs(days = 14): Promise<CVEItem[]> {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - days);

  const pubStartDate = start.toISOString().split('.')[0] + '.000';
  const pubEndDate = end.toISOString().split('.')[0] + '.000';

  const url = `${NVD_BASE}?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}&resultsPerPage=100`;

  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      console.error('NVD API error:', response.status, response.statusText);
      return getFallbackCVEs();
    }

    const data = (await response.json()) as Record<string, unknown>;
    const cves = parseNvdResponse(data);

    return cves.sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  } catch (err) {
    console.error('NVD fetch failed:', err);
    return getFallbackCVEs();
  }
}

function getFallbackCVEs(): CVEItem[] {
  return [
    {
      id: 'CVE-2024-3400',
      description:
        'Palo Alto Networks PAN-OS command injection vulnerability in GlobalProtect gateway.',
      cvssScore: 10.0,
      severity: 'CRITICAL',
      published: '2024-04-12T00:00:00.000',
      affectedProducts: ['paloalto:pan-os'],
      affectedCount: 1,
      exploitability: '3.9',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-3094',
      description:
        'Malicious code in upstream xz/liblzma leading to SSH backdoor in affected Linux distributions.',
      cvssScore: 10.0,
      severity: 'CRITICAL',
      published: '2024-03-29T00:00:00.000',
      affectedProducts: ['tukaani:xz', 'fedoraproject:fedora', 'debian:debian_linux'],
      affectedCount: 3,
      exploitability: '3.9',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-21762',
      description:
        'Fortinet FortiOS out-of-bounds write in sslvpnd allowing remote code execution.',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      published: '2024-02-08T00:00:00.000',
      affectedProducts: ['fortinet:fortios'],
      affectedCount: 1,
      exploitability: '3.9',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-6387',
      description:
        'OpenSSH regreSSHion signal handler race condition enabling unauthenticated RCE on glibc Linux.',
      cvssScore: 8.1,
      severity: 'HIGH',
      published: '2024-07-01T00:00:00.000',
      affectedProducts: ['openbsd:openssh'],
      affectedCount: 1,
      exploitability: '2.2',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-4577',
      description:
        'PHP CGI argument injection vulnerability on Windows enabling remote code execution.',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      published: '2024-06-06T00:00:00.000',
      affectedProducts: ['php:php'],
      affectedCount: 1,
      exploitability: '3.9',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-38112',
      description:
        'Windows MSHTML spoofing vulnerability used in phishing and drive-by download attacks.',
      cvssScore: 7.5,
      severity: 'HIGH',
      published: '2024-07-09T00:00:00.000',
      affectedProducts: ['microsoft:windows_10', 'microsoft:windows_11'],
      affectedCount: 2,
      exploitability: '2.8',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-20399',
      description:
        'Cisco NX-OS CLI command injection allowing authenticated attackers to execute commands as root.',
      cvssScore: 7.2,
      severity: 'HIGH',
      published: '2024-04-24T00:00:00.000',
      affectedProducts: ['cisco:nx-os'],
      affectedCount: 1,
      exploitability: '1.2',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    },
    {
      id: 'CVE-2024-21413',
      description:
        'Microsoft Outlook MonikerLink remote code execution via preview pane without user interaction.',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      published: '2024-02-13T00:00:00.000',
      affectedProducts: ['microsoft:outlook', 'microsoft:office'],
      affectedCount: 2,
      exploitability: '3.9',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H',
    },
  ];
}
