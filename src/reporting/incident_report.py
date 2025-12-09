import os
import json
import logging
from datetime import datetime
from typing import Dict


class IncidentReporter:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def save_incident(self, incident: Dict) -> str:
        """
        Sauvegarde l'incident en JSON dans un fichier timestampé.
        Retourne le chemin du fichier.
        """
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        attack_type = incident.get("attack_type", "unknown").replace(" ", "_")
        filename = f"{ts}_{attack_type}.json"
        path = os.path.join(self.base_dir, filename)

        # On enlève les objets non sérialisables (ex: datetime)
        serializable = self._make_serializable(incident)

        with open(path, "w") as f:
            json.dump(serializable, f, indent=2)

        logging.info("Incident sauvegardé: %s", path)
        return path

    def _make_serializable(self, incident: Dict) -> Dict:
        event = incident.get("event", {})
        event_copy = dict(event)
        ts = event_copy.get("timestamp")
        if ts is not None:
            event_copy["timestamp"] = ts.isoformat()

        inc_copy = dict(incident)
        inc_copy["event"] = event_copy
        return inc_copy
