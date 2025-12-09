import logging
from typing import Optional, Dict, Any

import requests


class WebhookAlerter:
    """
    Alerte générique via Webhook (Discord, Slack, custom, etc.).
    Envoie un POST JSON vers l'URL configurée.
    """

    def __init__(
        self,
        url: str,
        enabled: bool = True,
        timeout_seconds: int = 5,
        verify_tls: bool = True,
    ):
        self.url = url
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls

    def send_alert(
        self,
        title: str,
        body: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.enabled:
            logging.debug("Webhook désactivé, alerte ignorée.")
            return

        if not self.url:
            logging.warning("URL Webhook non configurée, alerte ignorée.")
            return

        payload = {
            "title": title,
            "message": body,
        }

        if extra:
            payload["extra"] = extra

        try:
            resp = requests.post(
                self.url,
                json=payload,
                timeout=self.timeout_seconds,
                verify=self.verify_tls,
            )
            if 200 <= resp.status_code < 300:
                logging.info("Alerte Webhook envoyée (%s)", resp.status_code)
            else:
                logging.warning(
                    "Webhook retourné statut HTTP %s: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception as e:
            logging.error("Erreur lors de l'envoi Webhook: %s", e)
