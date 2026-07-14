"""Deterministic senior-analyst responses grounded in retrieved context.

Used when Bedrock is disabled or unavailable so Ask AI still returns
evidence-based structured JSON from DynamoDB-backed dashboard data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ask_ai.schemas import AskResponse, PriorityItem, RiskIntelligenceResponse


def _compute_risk_score(stats: Dict[str, Any]) -> float:
    total = float(stats.get("uniqueCVEs") or stats.get("totalCVEs") or 0)
    if total <= 0:
        return 0.0
    weighted = (
        float(stats.get("criticalCVEs") or 0) * 10
        + float(stats.get("highCVEs") or 0) * 7
        + float(stats.get("mediumCVEs") or 0) * 4
        + float(stats.get("lowCVEs") or 0) * 2
    )
    avg = float(stats.get("averageCVSS") or 0)
    raw = (weighted / max(total, 1.0)) * (avg / 10.0) * 10.0
    # KEV / EPSS uplift
    kev = float(stats.get("kevFindings") or 0)
    high_epss = float(stats.get("highEpssFindings") or 0)
    uplift = min(25.0, kev * 2.5 + high_epss * 1.5)
    return round(min(100.0, raw + uplift), 1)


def _refs_from_findings(findings: List[Dict[str, Any]]) -> List[str]:
    refs: List[str] = []
    for f in findings[:6]:
        cid = f.get("cveId")
        if cid:
            refs.append(str(cid))
        if f.get("kev"):
            refs.append("CISA KEV")
        epss = f.get("epss")
        if epss and float(epss) >= 0.1:
            refs.append(f"EPSS {round(float(epss) * 100)}%")
    # preserve order, unique
    seen = set()
    out: List[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def build_ask_response(question: str, context: Dict[str, Any]) -> AskResponse:
    intent = context.get("intent") or "general"
    stats = context.get("stats") or {}
    risk = _compute_risk_score(stats)

    builders = {
        "summarize_findings": _summarize,
        "patch_first": _patch_first,
        "highest_risk_assets": _highest_assets,
        "explain_cve": _explain_cve,
        "explain_host": _explain_host,
        "internet_facing": _internet_facing,
        "mitigations": _mitigations,
        "risk_score": _risk_score,
        "general": _general,
    }
    builder = builders.get(intent, _general)
    response = builder(question, context, risk)
    response.intent = intent
    response.mode = "deterministic"
    response.markdown = _to_markdown(response)
    return response


def build_risk_intelligence(context: Dict[str, Any]) -> RiskIntelligenceResponse:
    stats = context.get("stats") or {}
    risk = _compute_risk_score(stats)
    assets = context.get("highestRiskAssets") or []
    findings = context.get("topFindings") or []
    factors = context.get("riskFactors") or []

    priority_reasons = []
    for a in assets[:5]:
        reasons = []
        if a.get("kevCount"):
            reasons.append(f"{a['kevCount']} KEV finding(s)")
        if a.get("maxCvss"):
            reasons.append(f"max CVSS {a['maxCvss']}")
        if a.get("cveCount"):
            reasons.append(f"{a['cveCount']} CVE(s)")
        label = a.get("hostname") or a.get("ip") or "Unknown asset"
        priority_reasons.append(
            {
                "asset": label,
                "ip": a.get("ip"),
                "reason": "; ".join(reasons) or "Elevated external exposure",
                "maxCvss": a.get("maxCvss"),
                "cveCount": a.get("cveCount"),
                "kevCount": a.get("kevCount"),
            }
        )

    top_critical = []
    for f in findings[:6]:
        top_critical.append(
            {
                "cveId": f.get("cveId"),
                "asset": f.get("ip"),
                "cvss": f.get("cvss"),
                "severity": f.get("severity"),
                "kev": f.get("kev"),
                "epss": f.get("epss"),
                "summary": f.get("summary"),
            }
        )

    remediation: List[str] = []
    for f in findings[:5]:
        bits = [f"Remediate {f.get('cveId')}"]
        if f.get("ip"):
            bits.append(f"on {f.get('ip')}")
        if f.get("product"):
            bits.append(f"({f.get('product')})")
        if f.get("kev"):
            bits.append("— CISA KEV priority")
        remediation.append(" ".join(bits))
    if not remediation:
        remediation.append("No critical remediations queued from the latest scan.")

    threat = list(factors)
    kev_findings = [f for f in findings if f.get("kev")]
    if kev_findings:
        threat.append(
            f"Actively exploited CVEs in scope: {', '.join(str(f.get('cveId')) for f in kev_findings[:4])}."
        )
    high_epss = [f for f in findings if (f.get("epss") or 0) >= 0.1]
    if high_epss:
        threat.append(
            f"Elevated EPSS on {', '.join(str(f.get('cveId')) for f in high_epss[:4])}."
        )

    summary = (
        f"External footprint risk score is {risk}/100 across "
        f"{stats.get('vulnerableIPs', 0)} vulnerable assets and "
        f"{stats.get('uniqueCVEs', 0)} unique CVEs "
        f"({stats.get('criticalCVEs', 0)} critical, {stats.get('kevFindings', 0)} KEV)."
    )

    return RiskIntelligenceResponse(
        summary=summary,
        riskScore=risk,
        highestRiskAssets=priority_reasons,
        topCriticalFindings=top_critical,
        threatIntel=threat,
        prioritizedRemediation=remediation,
        references=_refs_from_findings(findings),
        mode="deterministic",
    )


def _summarize(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    stats = context.get("stats") or {}
    findings = context.get("topFindings") or []
    assets = context.get("highestRiskAssets") or []
    factors = context.get("riskFactors") or []

    summary = (
        f"Scan posture: risk score {risk}/100 with {stats.get('uniqueCVEs', 0)} unique CVEs "
        f"on {stats.get('vulnerableIPs', 0)} internet-observed assets. "
        f"{stats.get('criticalCVEs', 0)} critical and {stats.get('kevFindings', 0)} CISA KEV findings drive urgency."
    )
    priority = [
        PriorityItem(
            asset=str(a.get("hostname") or a.get("ip")),
            reason=f"max CVSS {a.get('maxCvss')}; {a.get('cveCount')} CVE(s)"
            + (f"; {a.get('kevCount')} KEV" if a.get("kevCount") else ""),
        )
        for a in assets[:5]
    ]
    remediation = [
        f"Patch {f.get('cveId')} on {f.get('ip')}"
        + (" (KEV)" if f.get("kev") else "")
        for f in findings[:5]
    ]
    return AskResponse(
        summary=summary,
        riskScore=risk,
        priority=priority,
        remediation=remediation or ["Continue monitoring; no high-priority patch queue items."],
        threatIntel=factors,
        references=_refs_from_findings(findings),
    )


def _patch_first(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    queue = context.get("patchQueue") or context.get("topFindings") or []
    priority: List[PriorityItem] = []
    remediation: List[str] = []
    threat: List[str] = []
    refs: List[str] = []

    for item in queue[:6]:
        cid = item.get("cveId")
        asset = item.get("asset") or item.get("ip")
        reasons = item.get("reasons") or []
        reason = "; ".join(reasons) if reasons else f"CVSS {item.get('cvss')}"
        priority.append(PriorityItem(asset=f"{cid} @ {asset}", reason=reason))
        step = f"1st priority: remediate {cid} on {asset}"
        if item.get("product"):
            step += f" ({item.get('product')})"
        remediation.append(step)
        if item.get("kev"):
            threat.append(f"{cid} is on CISA KEV — treat as actively exploited.")
        if cid:
            refs.append(str(cid))
        if item.get("kev"):
            refs.append("CISA KEV")
        if (item.get("epss") or 0) >= 0.1:
            refs.append(f"EPSS {round(float(item['epss']) * 100)}%")

    summary = (
        "Patch order is driven by CISA KEV, EPSS exploit probability, CVSS severity, "
        f"and asset exposure. Current environment risk score: {risk}/100."
        if queue
        else "No prioritized patch candidates were found in the current scan set."
    )
    return AskResponse(
        summary=summary,
        riskScore=risk,
        priority=priority,
        remediation=remediation or ["No patch actions queued."],
        threatIntel=threat or ["No KEV/high-EPSS urgency signals in the top queue."],
        references=_unique(refs),
    )


def _highest_assets(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    assets = context.get("highestRiskAssets") or []
    priority = [
        PriorityItem(
            asset=str(a.get("hostname") or a.get("ip")),
            reason=(
                f"IP {a.get('ip')}; {a.get('cveCount')} CVE(s); max CVSS {a.get('maxCvss')}"
                + (f"; {a.get('kevCount')} KEV" if a.get("kevCount") else "")
            ),
        )
        for a in assets[:6]
    ]
    remediation = [
        f"Isolate/review {a.get('ip')} and remediate its highest-CVSS services first."
        for a in assets[:4]
    ]
    return AskResponse(
        summary=f"Highest-risk assets by KEV count, max CVSS, and CVE density. Risk score {risk}/100.",
        riskScore=risk,
        priority=priority,
        remediation=remediation or ["No vulnerable assets ranked."],
        threatIntel=context.get("riskFactors") or [],
        references=[],
    )


def _explain_cve(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    cve = context.get("cve") or {}
    if cve.get("notFound"):
        return AskResponse(
            summary=f"No finding for {cve.get('cveId')} in the current footprint dataset.",
            riskScore=risk,
            remediation=["Confirm the CVE ID or refresh the dashboard scan data."],
            threatIntel=[],
            references=[str(cve.get("cveId"))] if cve.get("cveId") else [],
        )

    cid = cve.get("cveId")
    summary = (
        f"{cid} (CVSS {cve.get('cvss')}, {cve.get('severity')}) — {cve.get('summary') or 'No description available.'} "
        f"Present on {cve.get('instanceCount', 0)} instance(s) across "
        f"{len(cve.get('affectedAssets') or [])} asset(s)."
    )
    threat: List[str] = []
    if cve.get("kev"):
        threat.append(f"{cid} is listed in CISA KEV (known active exploitation).")
    if (cve.get("epss") or 0) >= 0.1:
        threat.append(f"EPSS indicates elevated exploitation probability ({round(float(cve['epss']) * 100)}%).")
    if cve.get("samplePorts"):
        threat.append(f"Observed on ports: {', '.join(str(p) for p in cve['samplePorts'][:6])}.")

    remediation = [
        f"Apply vendor patches for {', '.join(cve.get('products') or ['affected software'])}.",
        "Validate fix on all listed assets and re-scan.",
        "If internet-facing, restrict exposure until patched.",
    ]
    priority = [
        PriorityItem(asset=str(ip), reason=f"Hosts {cid}")
        for ip in (cve.get("affectedAssets") or [])[:5]
    ]
    refs = [str(cid)]
    if cve.get("kev"):
        refs.append("CISA KEV")
    if (cve.get("epss") or 0) >= 0.1:
        refs.append(f"EPSS {round(float(cve['epss']) * 100)}%")

    return AskResponse(
        summary=summary,
        riskScore=risk,
        priority=priority,
        remediation=remediation,
        threatIntel=threat,
        references=refs,
    )


def _explain_host(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    host = context.get("host") or {}
    if host.get("notFound"):
        return AskResponse(
            summary=f"Host {host.get('ip')} was not found in the current scan set.",
            riskScore=risk,
            remediation=["Refresh dashboard data or verify the IP/hostname."],
        )

    label = (host.get("hostnames") or [None])[0] or host.get("ip")
    top = host.get("topCves") or []
    summary = (
        f"{label} ({host.get('ip')}) — OS: {host.get('os') or 'unknown'}; "
        f"{host.get('cveCount', 0)} CVE(s); risk level {host.get('riskLevel') or 'n/a'}. "
        f"Open ports: {', '.join(str(p) for p in (host.get('ports') or [])[:8]) or 'none listed'}."
    )
    priority = [
        PriorityItem(
            asset=str(c.get("id")),
            reason=f"CVSS {c.get('cvss')}"
            + ("; CISA KEV" if c.get("kev") else "")
            + (f"; EPSS {round(float(c['epss']) * 100)}%" if (c.get("epss") or 0) >= 0.1 else ""),
        )
        for c in top[:5]
    ]
    remediation = [
        f"Remediate {c.get('id')} on {host.get('ip')}" for c in top[:4]
    ] or ["No CVE remediations required for this host."]
    threat = []
    if any(c.get("kev") for c in top):
        threat.append("Host has KEV-listed vulnerabilities — prioritize immediately.")
    if host.get("services"):
        threat.append(f"Services observed: {', '.join(str(s) for s in host['services'][:6])}.")

    return AskResponse(
        summary=summary,
        riskScore=risk,
        priority=priority,
        remediation=remediation,
        threatIntel=threat,
        references=[str(c.get("id")) for c in top[:5] if c.get("id")],
    )


def _internet_facing(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    assets = context.get("internetFacingAssets") or context.get("highestRiskAssets") or []
    priority = [
        PriorityItem(
            asset=str(a.get("hostname") or a.get("ip")),
            reason=(
                f"Ports {', '.join(str(p) for p in (a.get('ports') or [])[:6]) or 'n/a'}; "
                f"{a.get('cveCount', 0)} CVE(s); risk {a.get('riskLevel') or 'n/a'}"
            ),
        )
        for a in assets[:8]
    ]
    remediation = [
        "Confirm business need for each exposed port; close unused services.",
        "Place high-CVE hosts behind allowlists or WAF where possible.",
        "Patch KEV/critical findings on exposed services before expanding exposure.",
    ]
    return AskResponse(
        summary=(
            f"{len(assets)} internet-observed assets are in scope for this footprint. "
            f"Environment risk score {risk}/100."
        ),
        riskScore=risk,
        priority=priority,
        remediation=remediation,
        threatIntel=context.get("riskFactors") or [],
        references=[],
    )


def _mitigations(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    findings = context.get("topFindings") or context.get("patchQueue") or []
    cve = context.get("cve")
    host = context.get("host")

    remediation: List[str] = [
        "Patch or upgrade affected software to vendor-fixed versions.",
        "Temporarily restrict internet exposure (firewall/ACL) for critical services.",
        "Verify compensating controls (WAF, MFA, network segmentation) while patches roll out.",
        "Re-scan after remediation and confirm KEV/critical counts decrease.",
    ]
    if cve and not cve.get("notFound"):
        remediation.insert(
            0,
            f"Primary: remediate {cve.get('cveId')} across {len(cve.get('affectedAssets') or [])} asset(s).",
        )
    if host and not host.get("notFound"):
        remediation.insert(
            0,
            f"Focus mitigations on host {host.get('ip')} with {host.get('cveCount', 0)} open CVE(s).",
        )

    priority = [
        PriorityItem(
            asset=str(f.get("cveId") or f.get("ip")),
            reason="Prioritized by KEV/EPSS/CVSS from scan evidence",
        )
        for f in findings[:5]
    ]
    return AskResponse(
        summary=f"Mitigation plan grounded in current findings. Risk score {risk}/100.",
        riskScore=risk,
        priority=priority,
        remediation=remediation,
        threatIntel=context.get("riskFactors") or [],
        references=_refs_from_findings(findings),
    )


def _risk_score(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    factors = context.get("riskFactors") or []
    findings = context.get("topFindings") or []
    summary = (
        f"The current risk score is {risk}/100. It rises with critical/high CVE density, "
        "average CVSS, CISA KEV presence, and elevated EPSS across internet-observed assets."
    )
    remediation = [
        "Drive down critical and KEV findings first — they dominate the score.",
        "Reduce average CVSS by remediating the highest-severity services.",
        "Re-scan to refresh the score after remediation waves.",
    ]
    priority = [
        PriorityItem(
            asset=str(f.get("cveId")),
            reason=f"Contributes via CVSS {f.get('cvss')}"
            + ("; KEV" if f.get("kev") else "")
            + (f"; EPSS {round(float(f['epss']) * 100)}%" if (f.get("epss") or 0) >= 0.1 else ""),
        )
        for f in findings[:5]
    ]
    return AskResponse(
        summary=summary,
        riskScore=risk,
        priority=priority,
        remediation=remediation,
        threatIntel=factors,
        references=_refs_from_findings(findings),
    )


def _general(question: str, context: Dict[str, Any], risk: float) -> AskResponse:
    # Fall back to summary posture for free-form analyst questions
    base = _summarize(question, context, risk)
    base.summary = (
        f"Analyst view for: “{question.strip()[:160]}”. " + base.summary
    )
    return base


def from_bedrock_payload(
    payload: Dict[str, Any],
    *,
    intent: str,
    fallback_risk: Optional[float] = None,
) -> AskResponse:
    priority_raw = payload.get("priority") or []
    priority: List[PriorityItem] = []
    for item in priority_raw:
        if isinstance(item, dict) and item.get("asset"):
            priority.append(
                PriorityItem(asset=str(item["asset"]), reason=str(item.get("reason") or ""))
            )

    risk = payload.get("riskScore")
    if risk is None:
        risk = fallback_risk

    response = AskResponse(
        summary=str(payload.get("summary") or "No summary returned."),
        riskScore=float(risk) if risk is not None else None,
        priority=priority,
        remediation=[str(x) for x in (payload.get("remediation") or [])],
        threatIntel=[str(x) for x in (payload.get("threatIntel") or [])],
        references=[str(x) for x in (payload.get("references") or [])],
        intent=intent,
        mode="bedrock",
    )
    response.markdown = _to_markdown(response)
    return response


def _to_markdown(response: AskResponse) -> str:
    lines = [response.summary, ""]
    if response.riskScore is not None:
        lines.append(f"**Risk score:** {response.riskScore}/100")
        lines.append("")
    if response.priority:
        lines.append("**Priority**")
        for p in response.priority:
            lines.append(f"- `{p.asset}` — {p.reason}")
        lines.append("")
    if response.remediation:
        lines.append("**Remediation**")
        for step in response.remediation:
            lines.append(f"- {step}")
        lines.append("")
    if response.threatIntel:
        lines.append("**Threat intelligence**")
        for t in response.threatIntel:
            lines.append(f"- {t}")
        lines.append("")
    if response.references:
        lines.append("**References:** " + ", ".join(response.references))
    return "\n".join(lines).strip()


def _unique(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
