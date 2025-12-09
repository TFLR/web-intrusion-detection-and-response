import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class SMTPAlerter:
    def __init__(
        self,
        server: str,
        port: int,
        from_email: str,
        to_email: str,
        username: str,
        password: str,
        enabled: bool = True,
    ):
        self.server = server
        self.port = port
        self.from_email = from_email
        self.to_email = to_email
        self.username = username
        self.password = password
        self.enabled = enabled
        self._last_body = None

    def send_alert(self, subject: str, body: str) -> None:
        if not self.enabled:
            logging.debug("SMTP désactivé, alerte ignorée.")
            return

        if not (self.username and self.password and self.from_email):
            logging.warning("SMTP mal configuré, alerte non envoyée.")
            return

        # Évite le spam si le message est identique au précédent
        if self._last_body == body:
            logging.debug("Alerte identique déjà envoyée, on ignore.")
            return

        msg = MIMEMultipart()
        msg["From"] = self.from_email
        msg["To"] = self.to_email or self.from_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.server, self.port) as s:
                s.starttls()
                s.login(self.username, self.password)
                s.sendmail(self.from_email, [self.to_email], msg.as_string())
            self._last_body = body
            logging.info("Alerte SMTP envoyée: %s", subject)
        except Exception as e:
            logging.error("Erreur lors de l'envoi SMTP: %s", e)
