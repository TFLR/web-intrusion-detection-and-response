from typing import Optional, Dict


def detect(event: Dict) -> Optional[Dict]:
    """
    Détection simple d'injection SQL.
    On cherche %27 et sqlmap dans la requête brute.
    """
    if event.get("source") != "apache":
        return None

    raw = event.get("raw", "")
    ip = event.get("ip")

    if "%27" in raw:
        incident = {
            "attack_type": "SQL Injection",
            "description": "Pattern %27 détecté dans la requête.",
            "severity": "HIGH",
            "ip": ip,
            "event": event,
        }
        # Si sqlmap est présent, on considère CRITICAL
        if "sqlmap" in raw.lower():
            incident["description"] += " sqlmap détecté."
            incident["severity"] = "CRITICAL"
        return incident

    return None
