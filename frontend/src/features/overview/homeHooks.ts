import { useDashboard } from "@/context/DashboardContext";

interface HomeInsight {
  title: string;
  value: string;
  detail: string;
  to: string;
}

export function useHomeKpis() {
  const { data, derived } = useDashboard();
  const critical = derived.cves.filter((c) => c.severity === "critical").length;
  const openFixes = derived.solutions.filter((s) => s.status === "open").length;
  const highRiskProviders = derived.vendors.filter((v) => v.riskScore >= 70).length;

  return [
    {
      label: "Vulnerabilities",
      value: String(data.stats.totalCVEs),
      tone: critical > 0 ? "critical" : "neutral",
      hint: `${critical} critical`,
      to: "/cves",
    },
    {
      label: "Scanned assets",
      value: String(derived.ips.length),
      tone: "neutral",
      hint: `${derived.ips.filter((ip) => ip.criticalCount > 0).length} with critical findings`,
      to: "/ips",
    },
    {
      label: "Remediations",
      value: String(openFixes),
      tone: openFixes > 0 ? "high" : "neutral",
      hint: "Prioritized remediation",
      to: "/solutions",
    },
    {
      label: "High-risk providers",
      value: String(highRiskProviders),
      tone: highRiskProviders > 0 ? "high" : "neutral",
      hint: "Software vendors",
      to: "/vendors",
    },
  ] as const;
}

export function useHomeInsights(): HomeInsight[] {
  const { data, derived } = useDashboard();
  const critical = derived.cves.filter((c) => c.severity === "critical").length;
  const systemsWithCritical = derived.ips.filter((ip) => ip.criticalCount > 0).length;
  const openFixes = derived.solutions.filter((s) => s.status === "open").length;
  const topProvider = derived.vendors[0];

  return [
    {
      title: "IP assets monitored",
      value: String(derived.ips.length),
      detail: `${systemsWithCritical} systems with critical severity findings`,
      to: "/ips",
    },
    {
      title: "Vulnerabilities",
      value: String(data.stats.totalCVEs),
      detail: `${critical} rated critical (CVSS 9.0+)`,
      to: "/cves",
    },
    {
      title: "Remediations",
      value: String(derived.solutions.length),
      detail: `${openFixes} not yet started`,
      to: "/solutions",
    },
    {
      title: "Software providers",
      value: String(derived.vendors.length),
      detail: topProvider ? `Highest risk: ${topProvider.name}` : "No product data",
      to: "/vendors",
    },
  ];
}
