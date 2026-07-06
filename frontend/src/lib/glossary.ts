export type GlossaryCategory =
  | 'vulnerabilities'
  | 'metrics'
  | 'remediation'
  | 'data'
  | 'threats';

export interface GlossaryEntry {
  id: string;
  term: string;
  summary: string;
  detail: string;
}

export interface GlossarySection {
  id: GlossaryCategory;
  title: string;
  description: string;
  entries: GlossaryEntry[];
}

export const GLOSSARY_SECTIONS: GlossarySection[] = [
  {
    id: 'vulnerabilities',
    title: 'Vulnerabilities & scoring',
    description: 'How security issues are identified and ranked.',
    entries: [
      {
        id: 'cve',
        term: 'CVE',
        summary: 'A publicly cataloged security flaw with a unique identifier.',
        detail:
          'Common Vulnerabilities and Exposures (CVE) IDs look like CVE-2024-1234. Each ID refers to one known weakness. The same CVE can appear on multiple hosts or ports in your footprint — the dashboard tracks both unique CVEs and total exposure instances.',
      },
      {
        id: 'cvss',
        term: 'CVSS',
        summary: 'A 0–10 severity score for how bad a vulnerability is on paper.',
        detail:
          'The Common Vulnerability Scoring System (CVSS) estimates technical impact. The dashboard maps scores to bands: Critical (9.0+), High (7.0–8.9), Medium (4.0–6.9), and Low (below 4.0). Higher CVSS means higher priority, but it does not measure whether attackers are actively exploiting the flaw.',
      },
      {
        id: 'kev',
        term: 'KEV (Known Exploited Vulnerabilities)',
        summary: 'CVEs CISA has confirmed are actively exploited in the wild.',
        detail:
          'The U.S. Cybersecurity and Infrastructure Security Agency (CISA) maintains a KEV catalog of vulnerabilities with evidence of real-world exploitation. Findings flagged as KEV should be remediated urgently, even when their CVSS score is moderate.',
      },
      {
        id: 'epss',
        term: 'EPSS',
        summary: 'A probability score that a CVE will be exploited in the next 30 days.',
        detail:
          'The Exploit Prediction Scoring System (EPSS) uses threat intelligence and vulnerability traits to estimate exploitation likelihood (0–100%). The dashboard highlights findings with EPSS ≥ 10% as “High EPSS.” EPSS complements CVSS: CVSS measures impact, EPSS measures likelihood.',
      },
      {
        id: 'verified',
        term: 'Verified exposure',
        summary: 'Shodan confirmed the service or vulnerability on that host.',
        detail:
          'When scan metadata marks an exposure as verified, Shodan has additional confidence the service exists on the internet-facing host. Unverified records may still be useful but deserve extra validation before remediation.',
      },
    ],
  },
  {
    id: 'metrics',
    title: 'Dashboard metrics',
    description: 'What the numbers on the home page mean.',
    entries: [
      {
        id: 'risk-score',
        term: 'Risk score',
        summary: 'A 0–100 rollup of severity mix and average CVSS across findings.',
        detail:
          'The risk score weights critical and high findings more heavily and factors in average CVSS. It is a quick posture indicator — use it for trends, not as a compliance grade.',
      },
      {
        id: 'unique-cves',
        term: 'Unique CVEs',
        summary: 'Distinct vulnerability IDs in your dataset.',
        detail:
          'If CVE-2023-1234 appears on ten hosts, it counts once as a unique CVE but ten times as exposure instances. Unique CVEs show breadth of weakness types; instances show total exposure.',
      },
      {
        id: 'exposure-instances',
        term: 'Exposure instances',
        summary: 'Total host/port findings — the same CVE on multiple assets counts multiple times.',
        detail:
          'Each row in the underlying scan data that links a CVE to a host (and often a port) is one instance. Remediation work may need to happen per asset even when the CVE ID is the same.',
      },
      {
        id: 'at-risk-assets',
        term: 'At-risk assets',
        summary: 'Hosts that have at least one critical-severity finding.',
        detail:
          'An asset is “at risk” when any associated CVE maps to the Critical CVSS band. Review these hosts first on the IP assets page.',
      },
      {
        id: 'discovery-hosts',
        term: 'Discovery-only hosts',
        summary: 'Hosts seen in scans without a linked CVE finding.',
        detail:
          'DNS discovery and port scans can record hosts, services, and ports before a CVE is attached. These assets still expand your footprint picture and may warrant monitoring.',
      },
      {
        id: 'observation-timeline',
        term: 'Observation timeline',
        summary: 'How findings were observed over time, or a snapshot breakdown when data spans one window.',
        detail:
          'When scan timestamps cover multiple days, the home page charts findings per day. For a single day with varied times, it groups by hour. If everything was observed in one window, the panel switches to scan sources, ports, or exploitability signals from your live data — never placeholder values.',
      },
    ],
  },
  {
    id: 'remediation',
    title: 'Remediation workflow',
    description: 'Tracking fix progress for critical and high findings.',
    entries: [
      {
        id: 'remediation-statuses',
        term: 'Remediation statuses',
        summary: 'Workflow labels you can assign on the Remediations page.',
        detail:
          'Not started — no work begun. Under review — triaged and owned. In progress — fix underway. Done — resolved or accepted risk documented. Status changes are saved in your browser until server-side tracking is added.',
      },
      {
        id: 'priority-queue',
        term: 'Priority queue',
        summary: 'Top critical/high items ranked by KEV, EPSS, and CVSS.',
        detail:
          'The home page queue is read-only for status. It surfaces what to look at first; update status from the Remediations page. Known-exploited (KEV) and high-EPSS items rise to the top.',
      },
      {
        id: 'pending-remediations',
        term: 'Pending remediations',
        summary: 'Items still in “Not started” or “Under review.”',
        detail:
          'This count drives the primary metric on the home page. You can configure which statuses count as pending in Settings → Remediation statuses.',
      },
    ],
  },
  {
    id: 'data',
    title: 'Data & scans',
    description: 'Where dashboard data comes from.',
    entries: [
      {
        id: 'scan-sources',
        term: 'Scan sources',
        summary: 'Which pipeline produced each finding.',
        detail:
          'Shodan CVE imports bring vulnerability metadata (CVSS, EPSS, products). DNS discovery finds hosts and services without CVEs. XML CVE scans add additional curated vulnerability records. Source mix is visible on the Analytics page.',
      },
      {
        id: 'ip-assets',
        term: 'IP assets',
        summary: 'Internet-facing addresses observed for your organization.',
        detail:
          'Each asset aggregates hostnames, domains, ports, services, products, and CVEs seen on that address. Open the asset detail page for ASN, ISP, OS, and scan history fields when present.',
      },
      {
        id: 'geo-map',
        term: 'Geographic map',
        summary: 'Host locations from scan geolocation — on Analytics when useful.',
        detail:
          'The map plots vulnerable assets using country and city from scan data. When all hosts share one region (for example, a single campus), the map adds little on the home page — use Analytics for geography and focus the overview on prioritized lists and charts.',
      },
      {
        id: 'dynamodb',
        term: 'DynamoDB findings',
        summary: 'The live dataset behind this dashboard.',
        detail:
          'The API reads the enriched-database table (ip + cve_id keys), merges rows per host, and filters out placeholder NO_CVE discovery keys from vulnerability counts while still using them for host discovery.',
      },
    ],
  },
  {
    id: 'threats',
    title: 'Threat categories',
    description: 'How attack-type groupings are derived.',
    entries: [
      {
        id: 'threat-types',
        term: 'Threat categories',
        summary: 'Inferred groupings from CVE description text.',
        detail:
          'Categories such as remote code execution or injection are inferred by keyword patterns in CVE summaries — they are not separate fields from the scanner. Use them for communication and triage, not as ground truth.',
      },
    ],
  },
];
