"""Transform DynamoDB finding rows into the DashboardData shape the React app expects."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d+", re.IGNORECASE)
HOSTNAME_XML_PATTERN = re.compile(r'name="([^"]+)"')


def _pick(item: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _split_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = _as_str(value)
    if not text:
        return []
    return [part.strip() for part in text.replace("|", ",").replace(";", ",").split(",") if part.strip()]


def _parse_ports(value: Any) -> List[int]:
    ports: List[int] = []
    for part in _split_list(value):
        for token in part.split():
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                ports.append(int(digits))
    return ports


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Informational"


def _normalize_severity(value: Any) -> str:
    text = _as_str(value).lower()
    if text.startswith("crit"):
        return "Critical"
    if text.startswith("high"):
        return "High"
    if text.startswith("med"):
        return "Medium"
    if text.startswith("low"):
        return "Low"
    if text.startswith("info"):
        return "Informational"
    try:
        return _score_to_severity(float(value))
    except (TypeError, ValueError):
        return "Informational"


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = _as_str(value).lower()
    return text in {"1", "true", "yes"}


def _parse_score(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _merge_unique(existing: List[Any], incoming: List[Any]) -> List[Any]:
    return list(dict.fromkeys([*existing, *incoming]))


def _is_real_cve_id(cve_id: str) -> bool:
    return bool(CVE_ID_PATTERN.match(cve_id))


def _parse_hostnames(item: Dict[str, Any]) -> List[str]:
    hostnames = _split_list(_pick(item, "hostnames", "hostname", "shodan_hostname"))
    if hostnames:
        return hostnames

    raw_json = _as_str(_pick(item, "hostnames_json"))
    if raw_json:
        return [name.strip() for name in HOSTNAME_XML_PATTERN.findall(raw_json) if name.strip()]

    single_hostname = _as_str(_pick(item, "hostname"))
    return [single_hostname] if single_hostname else []


def _parse_observed_at(value: Any) -> str:
    text = _as_str(value)
    if not text:
        return ""

    if text.isdigit():
        try:
            ts = int(text)
            if ts > 1_000_000_000_000:
                ts //= 1000
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            return text

    try:
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc).isoformat()
    except ValueError:
        return text


# TODO(pipeline-4): the AI Risk Analyzer Lambda (lambda_ai_risk_analyzer.py,
# PIPELINE4_FIELDS) already assumes DynamoDB rows may carry optional business/
# threat fields once Pipeline 4 lands: asset_criticality, business_unit,
# owner_team, environment, internet_exposed, exploit_maturity, threat_actors,
# malware, campaigns, remediation_status, first_seen, last_seen. Confirm those
# names against Pipeline 4's actual output before wiring them in here — if they
# match, add each to the relevant _pick(item, ...) call below (_build_cve for
# CVE-level fields, _merge_ip_record for host-level fields), then extend
# SourceCVE / SourceIPRecord in frontend/src/types/data.ts and thread them
# through adapters.ts's toAnalysisFindingsFromData (frontend/src/features/ask-ai/
# findings.ts) so the Lambda actually receives them — the AnalysisFinding type
# there already has the matching optional fields, they're just unpopulated until
# this transform passes them through. Do not guess field names ahead of the real
# schema; only these two files (this one and the Lambda) should need to change.


def _build_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve_id = _as_str(_pick(item, "cve_id", "cve", "original_cve_id"))
    if not cve_id or not _is_real_cve_id(cve_id):
        return None

    score = _parse_score(_pick(item, "cvss", "cve_score", "score", "cvss_v2"))
    severity_raw = _pick(item, "cvss_severity", "severity", "risk_level")
    severity = _normalize_severity(severity_raw) if severity_raw else _score_to_severity(score)

    ports = _parse_ports(_pick(item, "port", "port_id", "ports"))
    epss = _parse_score(_pick(item, "epss"))
    kev = _pick(item, "kev", "known_exploited")

    ranking_epss = _parse_score(_pick(item, "ranking_epss"))
    verified_raw = _pick(item, "verified")
    product = _as_str(_pick(item, "product", "products"))
    service = _as_str(_pick(item, "service_name", "service"))

    return {
        "id": cve_id.upper(),
        "score": score,
        "severity": severity,
        "publishedDate": _parse_observed_at(_pick(item, "observed_at", "published_date", "published", "processed_at", "timestamp")),
        "lastUpdated": _parse_observed_at(_pick(item, "processed_at", "last_updated", "updated")) or None,
        "summary": _as_str(_pick(item, "summary", "description")) or None,
        "kev": _parse_bool(kev) if kev is not None else None,
        "epss": round(epss, 5) if epss > 0 else None,
        "rankingEpss": round(ranking_epss, 5) if ranking_epss > 0 else None,
        "port": ports[0] if ports else None,
        "product": product or None,
        "service": service or None,
        "verified": _parse_bool(verified_raw) if verified_raw is not None else None,
    }


def _compute_risk_level(cves: List[Dict[str, Any]]) -> str:
    if not cves:
        return "Informational"
    return max(cves, key=lambda cve: SEVERITY_ORDER.get(cve["severity"], 0))["severity"]


def _empty_ip_record(ip: str) -> Dict[str, Any]:
    return {
        "ip": ip,
        "organization": "",
        "country": "",
        "city": None,
        "asn": None,
        "hostnames": [],
        "domains": [],
        "operatingSystem": None,
        "ports": [],
        "transport": [],
        "services": [],
        "products": [],
        "versions": [],
        "cves": [],
        "riskLevel": "Informational",
        "tags": [],
        "vulnerabilities": [],
        "openPorts": [],
        "isp": None,
        "timestamp": None,
        "summary": None,
        "lastSeen": None,
        "hostStatus": None,
        "scanTypes": [],
    }


def _merge_ip_record(existing: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
    cve = _build_cve(item)
    ports = _parse_ports(_pick(item, "port", "port_id", "ports", "open_ports"))
    open_ports = _parse_ports(_pick(item, "open_ports"))
    port_state = _as_str(_pick(item, "port_state")).lower()

    merged_cves = list(existing["cves"])
    if cve:
        merged_cves = [c for c in merged_cves if c["id"] != cve["id"]]
        merged_cves.append(cve)

    org = _as_str(_pick(item, "org", "organization"))
    country = _as_str(_pick(item, "location_country_code", "country", "country_code"))
    city = _as_str(_pick(item, "location_city", "city"))
    asn = _as_str(_pick(item, "asn"))
    hostnames = _parse_hostnames(item)
    domains = _split_list(_pick(item, "domains", "domain"))
    operating_system = _as_str(_pick(item, "os", "operating_system", "operatingSystem"))
    transport = _split_list(_pick(item, "transport", "protocol"))
    services = _split_list(_pick(item, "service_name", "service", "services"))
    products = _split_list(_pick(item, "product", "products"))
    versions = _split_list(_pick(item, "version", "versions"))
    tags = _split_list(_pick(item, "tags", "tag"))
    vulnerabilities = _split_list(_pick(item, "vulnerabilities", "vulnerability"))
    isp = _as_str(_pick(item, "isp"))
    timestamp = _parse_observed_at(_pick(item, "observed_at", "processed_at", "timestamp", "last_seen", "lastSeen"))
    summary = _as_str(_pick(item, "summary", "description"))
    host_status = _as_str(_pick(item, "host_status")) or None
    scan_type = _as_str(_pick(item, "scan_type")) or None
    scan_types = list(existing.get("scanTypes", []))
    if scan_type:
        scan_types = _merge_unique(scan_types, [scan_type])

    discovered_open_ports = list(open_ports or ports) if port_state == "open" else []

    return {
        **existing,
        "organization": org or existing["organization"],
        "country": country or existing["country"],
        "city": city or existing.get("city"),
        "asn": asn or existing.get("asn"),
        "hostnames": _merge_unique(existing["hostnames"], hostnames),
        "domains": _merge_unique(existing.get("domains", []), domains),
        "operatingSystem": operating_system or existing.get("operatingSystem"),
        "ports": _merge_unique(existing["ports"], ports),
        "transport": _merge_unique(existing["transport"], transport),
        "services": _merge_unique(existing["services"], services),
        "products": _merge_unique(existing["products"], products),
        "versions": _merge_unique(existing["versions"], versions),
        "cves": merged_cves,
        "riskLevel": _compute_risk_level(merged_cves),
        "tags": _merge_unique(existing["tags"], tags),
        "vulnerabilities": _merge_unique(existing["vulnerabilities"], vulnerabilities),
        "openPorts": _merge_unique(existing["openPorts"], discovered_open_ports or (open_ports or ports)),
        "isp": isp or existing.get("isp"),
        "timestamp": timestamp or existing.get("timestamp"),
        "summary": summary or existing.get("summary"),
        "lastSeen": timestamp or existing.get("lastSeen"),
        "hostStatus": host_status or existing.get("hostStatus"),
        "scanTypes": scan_types,
    }


def _transform_rows_to_ips(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ip_map: Dict[str, Dict[str, Any]] = {}

    for item in items:
        ip = _as_str(_pick(item, "ip", "host_ip"))
        if not ip:
            continue
        existing = ip_map.get(ip, _empty_ip_record(ip))
        ip_map[ip] = _merge_ip_record(existing, item)

    return sorted(
        ip_map.values(),
        key=lambda ip: (len(ip["cves"]), len(ip["ports"]), len(ip["services"])),
        reverse=True,
    )


def _flatten_cves(ips: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for ip in ips:
        for cve in ip["cves"]:
            records.append(
                {
                    "cve": cve,
                    "ip": ip["ip"],
                    "organization": ip["organization"],
                    "country": ip["country"],
                    "operatingSystem": ip.get("operatingSystem"),
                    "port": cve.get("port") or (ip["ports"][0] if ip["ports"] else None),
                    "product": cve.get("product"),
                    "service": cve.get("service"),
                    "verified": cve.get("verified"),
                    "scanType": ip.get("scanTypes", [None])[0] if ip.get("scanTypes") else None,
                }
            )
    return records


def _compute_scan_sources(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        scan_type = _as_str(_pick(item, "scan_type"))
        if not scan_type:
            continue
        counts[scan_type] = counts.get(scan_type, 0) + 1
    return dict(sorted(counts.items(), key=lambda entry: entry[1], reverse=True))


def _parse_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _compute_stats(ips: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_cves = [cve for ip in ips for cve in ip["cves"]]
    scores = [cve["score"] for cve in all_cves if cve["score"] > 0]
    published_dates = sorted(
        date for date in (_parse_date(cve.get("publishedDate", "")) for cve in all_cves) if date
    )

    def count_by_severity(severity: str) -> int:
        return sum(1 for cve in all_cves if cve["severity"] == severity)

    vulnerable_ips = sum(1 for ip in ips if ip["cves"])
    discovered_hosts = sum(1 for ip in ips if ip["services"] or ip["ports"] or ip["hostnames"])
    discovery_only_hosts = sum(
        1 for ip in ips if not ip["cves"] and (ip["services"] or ip["ports"] or ip["hostnames"])
    )
    unique_cve_ids = {cve["id"] for ip in ips for cve in ip["cves"]}
    kev_findings = sum(1 for ip in ips for cve in ip["cves"] if cve.get("kev"))
    high_epss_findings = sum(1 for ip in ips for cve in ip["cves"] if (cve.get("epss") or 0) >= 0.1)
    verified_findings = sum(1 for ip in ips for cve in ip["cves"] if cve.get("verified"))

    return {
        "totalIPs": len(ips),
        "totalCVEs": len(all_cves),
        "uniqueCVEs": len(unique_cve_ids),
        "criticalCVEs": count_by_severity("Critical"),
        "highCVEs": count_by_severity("High"),
        "mediumCVEs": count_by_severity("Medium"),
        "lowCVEs": count_by_severity("Low"),
        "informationalCVEs": count_by_severity("Informational"),
        "averageCVSS": round(sum(scores) / len(scores), 1) if scores else 0,
        "highestCVSS": max(scores) if scores else 0,
        "newestVulnerability": published_dates[-1].isoformat() if published_dates else None,
        "oldestVulnerability": published_dates[0].isoformat() if published_dates else None,
        "uniqueOrganizations": len({ip["organization"] for ip in ips if ip["organization"]}),
        "uniqueCountries": len({ip["country"] for ip in ips if ip["country"]}),
        "vulnerableIPs": vulnerable_ips,
        "discoveredHosts": discovered_hosts,
        "discoveryOnlyHosts": discovery_only_hosts,
        "kevFindings": kev_findings,
        "highEpssFindings": high_epss_findings,
        "verifiedFindings": verified_findings,
    }


def findings_to_dashboard(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    ips = _transform_rows_to_ips(items)
    return {
        "ips": ips,
        "stats": _compute_stats(ips),
        "cveRecords": _flatten_cves(ips),
        "scanSourceCounts": _compute_scan_sources(items),
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "source": "dynamodb",
    }
