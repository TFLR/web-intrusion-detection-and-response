from typing import Optional, Dict


SCANNER_KEYWORDS = (
    "nikto",
    "acunetix",
    "nessus",
    "openvas",
    "netsparker",
    "arachni",
    "wpscan",
    "dirbuster",
    "dirb",
    "nmap",
    "whatweb",
    "sqlmap",
    "commix",
)


def detect(event: Dict) -> Optional[Dict]:
    """Détection générique de scanners web via l'user-agent ou la requête brute."""
    if event.get("source") != "apache":
        return None

    raw = event.get("raw", "")
    user_agent = event.get("user_agent") or ""
    text = (raw + "\n" + user_agent).lower()

    matched = next((kw for kw in SCANNER_KEYWORDS if kw in text), None)
    if not matched:
        return None

    return {
        "attack_type": "Scanner Web",
        "description": f"Signature scanner détectée: {matched}",
        "severity": "HIGH",
        "ip": event.get("ip"),
        "event": event,
    }
