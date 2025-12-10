from typing import Optional, Dict


SQLI_PATTERNS = (
    "%27", "%22", "' or 1=1", "' or '1'='1", " or 1=1 --",
    "union select", "information_schema", "sleep(", "benchmark(", "extractvalue(",
    "updatexml(", "load_file(", "outfile", "sqlmap",
)


def _is_sqli(raw: str) -> Optional[str]:
    lowered = raw.lower()
    for pattern in SQLI_PATTERNS:
        if pattern in lowered:
            return pattern
    return None


def detect(event: Dict) -> Optional[Dict]:
    """Détection enrichie d'injection SQL dans les requêtes Apache."""
    if event.get("source") != "apache":
        return None

    raw = event.get("raw", "")
    path = (event.get("path") or "").lower()
    combined = f"{raw}\n{path}"
    hit = _is_sqli(combined)
    if not hit:
        return None

    severity = "HIGH"
    description = f"Pattern SQLi détecté: {hit}"
    if "sqlmap" in combined:
        severity = "CRITICAL"
        description += " (sqlmap)"
    elif "sleep(" in combined or "benchmark(" in combined:
        severity = "HIGH"
        description += " (time-based)"

    return {
        "attack_type": "SQL Injection",
        "description": description,
        "severity": severity,
        "ip": event.get("ip"),
        "event": event,
    }
