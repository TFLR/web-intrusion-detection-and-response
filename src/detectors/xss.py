from typing import Optional, Dict


def detect(event: Dict) -> Optional[Dict]:
    """
    Détection très simple de XSS (<script>).
    On regarde dans les logs MySQL (requêtes envoyées).
    """
    if event.get("source") != "mysql":
        return None

    raw = event.get("raw", "").lower()
    if "<script>" in raw or "</script>" in raw:
        return {
            "attack_type": "XSS",
            "description": "Pattern <script> détecté dans la requête.",
            "severity": "MEDIUM",
            "ip": event.get("ip"),
            "event": event,
        }
    return None
