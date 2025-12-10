from typing import Optional, Dict


XSS_PATTERNS = (
    "<script", "</script", "onerror=", "onload=", "javascript:", "alert(",
    "<img", "<svg", "<iframe",
)


def detect(event: Dict) -> Optional[Dict]:
    """
    Détection XSS simple (MySQL ou logs applicatifs) sur le contenu brut / chemin.
    """
    raw = (event.get("raw") or "").lower()
    path = (event.get("path") or "").lower()

    # Filtrer pour les sources plausibles: mysql, apache, app web
    source = (event.get("source") or "").lower()
    if not any(s in source for s in ("mysql", "apache", "app", "web")):
        return None

    text = raw + "\n" + path
    if not any(p in text for p in XSS_PATTERNS):
        return None

    severity = "MEDIUM"
    if "<script" in text or "javascript:" in text:
        severity = "HIGH"

    return {
        "attack_type": "XSS",
        "description": "Patterns XSS suspects détectés dans la requête.",
        "severity": severity,
        "ip": event.get("ip"),
        "event": event,
    }
