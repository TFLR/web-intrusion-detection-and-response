from datetime import datetime
from typing import Optional, Dict, List


class BruteForceDetector:
    """
    Détection simple de brute force / flood HTTP basée sur:
    - nombre de requêtes par IP
    - dans une fenêtre temporelle donnée
    """

    def __init__(self, threshold: int = 20, window_seconds: int = 2):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # { ip: [timestamps récents] }
        self.history: Dict[str, List[datetime]] = {}

    def process_event(self, event: Dict) -> Optional[Dict]:
        if event.get("source") != "apache":
            return None

        ip = event.get("ip")
        ts = event.get("timestamp")
        if not ip or not ts:
            return None

        # Récupère l'historique de l'IP
        ip_hist = self.history.get(ip, [])

        # On garde uniquement les événements dans la fenêtre
        ip_hist = [t for t in ip_hist if (ts - t).total_seconds() <= self.window_seconds]
        ip_hist.append(ts)
        self.history[ip] = ip_hist

        if len(ip_hist) >= self.threshold:
            # On considère que c'est du brute force / DoS
            # On reset l'historique pour éviter le spam
            self.history[ip] = []
            return {
                "attack_type": "HTTP Flood / Brute Force",
                "description": f"{len(ip_hist)} requêtes en <= {self.window_seconds}s",
                "severity": "HIGH",
                "ip": ip,
                "event": event,
            }

        return None
