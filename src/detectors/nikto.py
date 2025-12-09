from typing import Optional, Dict


def detect(event: Dict) -> Optional[Dict]:
    """
    Détection de Nikto (user-agent ou signature dans la requête).
    """
    if event.get("source") != "apache":
        return None

    raw = event.get("raw", "").lower()
    if "nikto" in raw:
        return {
            "attack_type": "Nikto Scanner",
            "description": "Signature Nikto détectée dans les logs Apache.",
            "severity": "HIGH",
            "ip": event.get("ip"),
            "event": event,
        }
    return None
