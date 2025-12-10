import re
from typing import Dict, Optional


AUTH_PATTERNS = (
    "password authentication failed",
    "no pg_hba.conf entry",
    "PAM authentication failed",
    "LDAP authentication failed",
    "GSS authentication failed",
    "SASL authentication failed",
    "authentication failed for user",
    "invalid length of startup packet",
    "replication connection startup rejected",
    "connection matched pg_hba.conf entry",
    "FATAL:",
)

IP_REGEX = re.compile(r"host=([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
CLIENT_REGEX = re.compile(r"client=([0-9]{1,3}(?:\.[0-9]{1,3}){3})")


def detect(event: Dict) -> Optional[Dict]:
    source = (event.get("source") or "").lower()
    if "postgres" not in source:
        return None

    raw = event.get("raw", "")
    lowered = raw.lower()
    matched = next((p for p in AUTH_PATTERNS if p.lower() in lowered), None)
    if not matched:
        return None

    ip = event.get("ip")
    if not ip:
        match = IP_REGEX.search(raw) or CLIENT_REGEX.search(raw)
        if match:
            ip = match.group(1)

    severity = "MEDIUM"
    if (
        "no pg_hba.conf entry" in lowered
        or "invalid length of startup packet" in lowered
    ):
        severity = "HIGH"
    if "replication" in lowered:
        severity = "HIGH"
    if "pam" in lowered or "ldap" in lowered or "sasl" in lowered:
        severity = "HIGH"

    return {
        "attack_type": "PostgreSQL Auth Failure",
        "description": f"Signal PostgreSQL: {matched}",
        "severity": severity,
        "ip": ip,
        "event": event,
    }
