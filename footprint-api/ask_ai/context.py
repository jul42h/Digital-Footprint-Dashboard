"""Intent classification and selective context retrieval from dashboard findings."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

HIGH_EPSS = 0.1

INTENT_PATTERNS: List[Tuple[str, List[str]]] = [
    (
        "summarize_findings",
        ["summarize", "today", "overview", "executive", "what's happening", "what is happening"],
    ),
    (
        "patch_first",
        ["patch first", "what should i patch", "prioritize", "fix first", "remediate first"],
    ),
    (
        "highest_risk_assets",
        ["highest risk", "most at risk", "riskiest", "top assets", "critical assets"],
    ),
    (
        "explain_cve",
        ["explain this cve", "explain cve", "what is cve", "tell me about cve"],
    ),
    (
        "explain_host",
        ["explain this host", "explain host", "tell me about host", "about this ip", "about this asset"],
    ),
    (
        "internet_facing",
        ["internet-facing", "internet facing", "exposed", "external facing", "public facing"],
    ),
    (
        "mitigations",
        ["mitigation", "mitigate", "how do i fix", "recommend", "remediation steps", "how to remediate"],
    ),
    (
        "risk_score",
        ["risk score", "why is risk", "explain the risk", "current risk", "exposure score"],
    ),
]


def classify_intent(question: str, cve_id: Optional[str] = None, host: Optional[str] = None) -> str:
    q = question.lower().strip()
    for intent, keywords in INTENT_PATTERNS:
        if any(k in q for k in keywords):
            return intent
    if cve_id or re.search(r"\bcve-\d{4}-\d+\b", q, re.I):
        return "explain_cve"
    if host or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q):
        return "explain_host"
    return "general"


def _extract_cve_id(question: str, explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit.upper()
    match = re.search(r"\b(CVE-\d{4}-\d+)\b", question, re.I)
    return match.group(1).upper() if match else None


def _extract_host(question: str, explicit: Optional[str], ips: List[Dict[str, Any]]) -> Optional[str]:
    if explicit:
        return explicit
    ip_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", question)
    if ip_match:
        return ip_match.group(1)
    q = question.lower()
    for record in ips:
        for hostname in record.get("hostnames") or []:
            if hostname and hostname.lower() in q:
                return record.get("ip") or hostname
    return None


def _cvss(cve: Dict[str, Any]) -> float:
    try:
        return float(cve.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def _epss(cve: Dict[str, Any]) -> float:
    try:
        return float(cve.get("epss") or 0)
    except (TypeError, ValueError):
        return 0.0


def _priority_key(cve: Dict[str, Any]) -> Tuple[int, float, float]:
    kev = 1 if cve.get("kev") else 0
    return (kev, _epss(cve), _cvss(cve))


def _flatten_findings(dashboard: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for record in dashboard.get("cveRecords") or []:
        cve = record.get("cve") or {}
        rows.append(
            {
                "cveId": cve.get("id"),
                "cvss": _cvss(cve),
                "severity": cve.get("severity"),
                "summary": (cve.get("summary") or "")[:400],
                "kev": bool(cve.get("kev")),
                "epss": _epss(cve),
                "ip": record.get("ip"),
                "organization": record.get("organization"),
                "port": record.get("port") or cve.get("port"),
                "product": record.get("product") or cve.get("product"),
                "service": record.get("service") or cve.get("service"),
                "os": record.get("operatingSystem"),
                "verified": bool(record.get("verified") or cve.get("verified")),
            }
        )
    return rows


def _top_findings(findings: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    ranked = sorted(findings, key=lambda f: (_priority_key(f), f.get("cvss") or 0), reverse=True)
    # Deduplicate by CVE for summary views
    seen = set()
    unique: List[Dict[str, Any]] = []
    for row in ranked:
        cid = row.get("cveId")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        unique.append(row)
        if len(unique) >= limit:
            break
    return unique


def _host_context(dashboard: Dict[str, Any], host: str) -> Dict[str, Any]:
    for record in dashboard.get("ips") or []:
        if record.get("ip") == host or host in (record.get("hostnames") or []):
            cves = record.get("cves") or []
            ranked = sorted(cves, key=_priority_key, reverse=True)[:10]
            return {
                "ip": record.get("ip"),
                "hostnames": record.get("hostnames") or [],
                "organization": record.get("organization"),
                "country": record.get("country"),
                "city": record.get("city"),
                "os": record.get("operatingSystem"),
                "ports": record.get("openPorts") or record.get("ports") or [],
                "services": record.get("services") or [],
                "products": record.get("products") or [],
                "riskLevel": record.get("riskLevel"),
                "cveCount": len(cves),
                "topCves": [
                    {
                        "id": c.get("id"),
                        "cvss": _cvss(c),
                        "severity": c.get("severity"),
                        "kev": bool(c.get("kev")),
                        "epss": _epss(c),
                        "summary": (c.get("summary") or "")[:240],
                    }
                    for c in ranked
                ],
            }
    return {"ip": host, "notFound": True}


def _cve_context(dashboard: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
    matches = [f for f in _flatten_findings(dashboard) if (f.get("cveId") or "").upper() == cve_id.upper()]
    if not matches:
        return {"cveId": cve_id, "notFound": True}
    first = matches[0]
    assets = sorted({m.get("ip") for m in matches if m.get("ip")})
    return {
        "cveId": cve_id.upper(),
        "cvss": first.get("cvss"),
        "severity": first.get("severity"),
        "summary": first.get("summary"),
        "kev": first.get("kev"),
        "epss": first.get("epss"),
        "affectedAssets": assets[:15],
        "instanceCount": len(matches),
        "samplePorts": sorted({m.get("port") for m in matches if m.get("port")})[:10],
        "products": sorted({m.get("product") for m in matches if m.get("product")})[:8],
    }


def build_context(
    dashboard: Dict[str, Any],
    question: str,
    *,
    cve_id: Optional[str] = None,
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """Select only the slices of environment data needed for the question."""
    intent = classify_intent(question, cve_id=cve_id, host=host)
    stats = dashboard.get("stats") or {}
    findings = _flatten_findings(dashboard)
    ips = dashboard.get("ips") or []

    resolved_cve = _extract_cve_id(question, cve_id)
    resolved_host = _extract_host(question, host, ips)

    context: Dict[str, Any] = {
        "intent": intent,
        "stats": {
            "totalIPs": stats.get("totalIPs"),
            "vulnerableIPs": stats.get("vulnerableIPs"),
            "uniqueCVEs": stats.get("uniqueCVEs"),
            "criticalCVEs": stats.get("criticalCVEs"),
            "highCVEs": stats.get("highCVEs"),
            "kevFindings": stats.get("kevFindings"),
            "highEpssFindings": stats.get("highEpssFindings"),
            "averageCVSS": stats.get("averageCVSS"),
            "highestCVSS": stats.get("highestCVSS"),
        },
        "lastUpdated": dashboard.get("lastUpdated"),
    }

    if intent in {"summarize_findings", "risk_score", "general", "patch_first", "mitigations"}:
        context["topFindings"] = _top_findings(findings, limit=8)
        context["riskFactors"] = _risk_factors(stats, findings)

    if intent in {"highest_risk_assets", "internet_facing", "summarize_findings", "patch_first", "general"}:
        context["highestRiskAssets"] = _highest_risk_assets(ips, limit=6)

    if intent == "internet_facing":
        context["internetFacingAssets"] = _internet_facing(ips, limit=12)

    if intent in {"explain_cve", "mitigations"} or resolved_cve:
        target = resolved_cve or (context.get("topFindings") or [{}])[0].get("cveId")
        if target:
            context["cve"] = _cve_context(dashboard, target)

    if intent in {"explain_host", "mitigations"} or resolved_host:
        target_host = resolved_host
        if not target_host and context.get("highestRiskAssets"):
            target_host = context["highestRiskAssets"][0].get("ip")
        if target_host:
            context["host"] = _host_context(dashboard, target_host)

    if intent == "patch_first":
        context["patchQueue"] = _patch_queue(findings, limit=8)

    return context


def _risk_factors(stats: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[str]:
    factors: List[str] = []
    critical = int(stats.get("criticalCVEs") or 0)
    kev = int(stats.get("kevFindings") or 0)
    high_epss = int(stats.get("highEpssFindings") or 0)
    vuln_ips = int(stats.get("vulnerableIPs") or 0)
    if critical:
        factors.append(f"{critical} critical-severity CVEs inflate exposure.")
    if kev:
        factors.append(f"{kev} findings are on the CISA KEV list (active exploitation).")
    if high_epss:
        factors.append(f"{high_epss} findings have elevated EPSS (≥{int(HIGH_EPSS * 100)}%).")
    if vuln_ips:
        factors.append(f"{vuln_ips} internet-observed assets currently have open vulnerabilities.")
    if not factors and findings:
        factors.append("Residual medium/low findings remain across the external footprint.")
    if not factors:
        factors.append("No vulnerability findings were present in the latest scan payload.")
    return factors


def _highest_risk_assets(ips: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    ranked: List[Dict[str, Any]] = []
    for record in ips:
        cves = record.get("cves") or []
        if not cves:
            continue
        max_cvss = max((_cvss(c) for c in cves), default=0.0)
        kev_count = sum(1 for c in cves if c.get("kev"))
        ranked.append(
            {
                "ip": record.get("ip"),
                "hostname": (record.get("hostnames") or [None])[0],
                "cveCount": len(cves),
                "maxCvss": max_cvss,
                "kevCount": kev_count,
                "riskLevel": record.get("riskLevel"),
                "ports": (record.get("openPorts") or record.get("ports") or [])[:8],
                "os": record.get("operatingSystem"),
            }
        )
    ranked.sort(key=lambda a: (a.get("kevCount") or 0, a.get("maxCvss") or 0, a.get("cveCount") or 0), reverse=True)
    return ranked[:limit]


def _internet_facing(ips: List[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    # All Shodan-sourced assets in this dashboard are internet-observed.
    facing = []
    for record in ips:
        facing.append(
            {
                "ip": record.get("ip"),
                "hostname": (record.get("hostnames") or [None])[0],
                "ports": (record.get("openPorts") or record.get("ports") or [])[:10],
                "services": (record.get("services") or [])[:8],
                "cveCount": len(record.get("cves") or []),
                "riskLevel": record.get("riskLevel"),
            }
        )
    facing.sort(key=lambda a: a.get("cveCount") or 0, reverse=True)
    return facing[:limit]


def _patch_queue(findings: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    queue = []
    for row in _top_findings(findings, limit=limit):
        reasons = []
        if row.get("kev"):
            reasons.append("CISA KEV — known active exploitation")
        if (row.get("epss") or 0) >= HIGH_EPSS:
            reasons.append(f"EPSS {round((row.get('epss') or 0) * 100)}%")
        if (row.get("cvss") or 0) >= 9.0:
            reasons.append(f"Critical CVSS {row.get('cvss')}")
        elif (row.get("cvss") or 0) >= 7.0:
            reasons.append(f"High CVSS {row.get('cvss')}")
        queue.append(
            {
                "cveId": row.get("cveId"),
                "asset": row.get("ip"),
                "product": row.get("product"),
                "reasons": reasons or ["Highest relative severity in the scan set"],
                "cvss": row.get("cvss"),
                "kev": row.get("kev"),
                "epss": row.get("epss"),
            }
        )
    return queue
