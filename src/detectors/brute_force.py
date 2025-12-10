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

        method = (event.get("method") or "").upper()
        status_raw = event.get("status")
        path = (event.get("path") or "").lower()

        status = None
        try:
            status = int(status_raw) if status_raw is not None else None
        except ValueError:
            status = None

        # On cible de préférence les endpoints de login / auth ou les codes d'échec
        is_login_path = any(
            k in path for k in ("login", "auth", "signin", "wp-login", "admin")
        )
        is_fail_status = status in {401, 403, 429}
        is_post = method == "POST"

        # Si rien n'indique une auth ou un échec, on reste permissif mais on garde l'événement
        important = is_login_path or is_fail_status or is_post

        # Récupère l'historique de l'IP
        ip_hist = self.history.get(ip, [])

        # On garde uniquement les événements dans la fenêtre
        ip_hist = [
            t for t in ip_hist if (ts - t).total_seconds() <= self.window_seconds
        ]
        ip_hist.append(ts)
        self.history[ip] = ip_hist

        if len(ip_hist) >= self.threshold and important:
            # On considère que c'est du brute force / DoS ciblé
            # On reset l'historique pour éviter le spam
            self.history[ip] = []
            severity = "CRITICAL" if is_fail_status or is_login_path else "HIGH"
            description = (
                f"{len(ip_hist)} requêtes en <= {self.window_seconds}s"
                f" (path={path or '-'}, method={method or '-'}, status={status_raw or '-'})"
            )
            return {
                "attack_type": "HTTP Flood / Brute Force",
                "description": description,
                "severity": severity,
                "ip": ip,
                "event": event,
            }

        return None


def build_detector(cfg=None) -> "BruteForceDetector":
    threshold = getattr(cfg, "brute_force_threshold", 20)
    window_seconds = getattr(cfg, "brute_force_window", 2)
    return BruteForceDetector(threshold=threshold, window_seconds=window_seconds)
