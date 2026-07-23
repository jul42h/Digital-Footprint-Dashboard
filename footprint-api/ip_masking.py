"""Subnet-level IP and hostname masking for the 'viewer' role.

Responsibilities, deliberately kept separate:
  - mask_ip_display(ip): the human-readable text shown to a viewer
    ("10.20.30.5" -> "10.20.30.xxx"). Many real hosts can legitimately
    collide on this string once masked -- that's the point.
  - opaque_ip_token(ip): a stable, unique-per-host join/route key that
    replaces the real "ip" field in a viewer's response. Must never
    collide across two different real hosts, unlike the display text.
    HMAC-SHA256'd with a server-only salt so it isn't reversible without
    it -- an unsalted hash of a raw IPv4 address is brute-forceable in
    well under a minute given IPv4's ~4B address space.
  - mask_hostname(hostname): redacts the label(s) that identify one
    specific machine ("ipeer.ts.fresnostate.edu" -> "***.fresnostate.edu"),
    keeping the trailing domain -- same "show the org, hide the specific
    box" logic as mask_ip_display, and unlike IP there's no join/route key
    hiding behind it anywhere in the app, so there's nothing else to keep
    consistent.

mask_dashboard_for_viewer() is the entry point app.py calls. It returns a
NEW dashboard dict/lists/dicts and never mutates its input -- that input
is app.py's process-wide `_dashboard_cache`, shared across every request
(including concurrent admin/analyst ones) until the next refresh.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Dict, List

IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

IP_MASK_SALT = os.environ.get("IP_MASK_SALT")


def _require_salt() -> str:
    """Fail loudly rather than ever tokenizing IPs with a guessable/no salt."""
    if not IP_MASK_SALT:
        raise RuntimeError(
            "IP_MASK_SALT is not set. Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(64))"\n'
            "and set it as an environment variable before starting the API. "
            "Required because a viewer-role user requested the dashboard."
        )
    return IP_MASK_SALT


def mask_ip_display(ip: str) -> str:
    """Human-readable masked text: '10.20.30.5' -> '10.20.30.xxx'.

    Anything that isn't a plain IPv4 dotted-quad is redacted fully rather
    than guessed at, so we never leak part of an unrecognized address shape.
    """
    match = IPV4_PATTERN.match(ip)
    if not match:
        return "REDACTED"
    o1, o2, o3, _o4 = match.groups()
    return f"{o1}.{o2}.{o3}.xxx"


def opaque_ip_token(ip: str) -> str:
    """Stable, salted, non-reversible per-host token used as the join/route key."""
    digest = hmac.new(_require_salt().encode("utf-8"), ip.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"ip-{digest[:32]}"


def mask_hostname(hostname: str) -> str:
    """Redact the host-identifying label(s) of an FQDN, keep the domain.

    'ipeer.ts.fresnostate.edu' -> '***.fresnostate.edu'. Anything without
    at least two dot-separated labels is redacted fully rather than guessed
    at, mirroring mask_ip_display's fail-closed handling of odd input.
    """
    labels = [label for label in hostname.strip(".").split(".") if label]
    if len(labels) < 2:
        return "REDACTED"
    return f"***.{'.'.join(labels[-2:])}"


def mask_hostnames(hostnames: List[str]) -> List[str]:
    """Mask each hostname, de-duping same-domain collisions (order-preserving)."""
    return list(dict.fromkeys(mask_hostname(h) for h in hostnames if h))


def mask_dashboard_for_viewer(dashboard: Dict[str, Any]) -> Dict[str, Any]:
    """Return a masked copy of a dashboard payload for the viewer role.

    Builds new `ips`/`cveRecords` lists of new dicts -- never mutates
    `dashboard` itself, since callers pass the shared process-wide cache.
    """
    token_by_real_ip: Dict[str, str] = {}

    def token_for(real_ip: str) -> str:
        token = token_by_real_ip.get(real_ip)
        if token is None:
            token = opaque_ip_token(real_ip)
            token_by_real_ip[real_ip] = token
        return token

    masked_ips: List[Dict[str, Any]] = [
        {
            **entry,
            "ip": token_for(entry.get("ip", "")),
            "ipDisplay": mask_ip_display(entry.get("ip", "")),
            "hostnames": mask_hostnames(entry.get("hostnames", [])),
        }
        for entry in dashboard.get("ips", [])
    ]
    masked_cve_records: List[Dict[str, Any]] = [
        {
            **record,
            "ip": token_for(record.get("ip", "")),
            "ipDisplay": mask_ip_display(record.get("ip", "")),
        }
        for record in dashboard.get("cveRecords", [])
    ]

    return {**dashboard, "ips": masked_ips, "cveRecords": masked_cve_records}
