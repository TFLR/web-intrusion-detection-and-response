import logging
from logging.handlers import RotatingFileHandler
from typing import Dict

import detectors
from config import SEVERITY_ORDER, load_config
from log_watcher import build_event_from_source, iter_logs
from response.fail2ban import Fail2BanResponder
from response.iptables import IptablesResponder
from alerting.smtp_alert import SMTPAlerter
from alerting.webhook_alert import WebhookAlerter
from reporting.incident_report import IncidentReporter


def severity_ge(a: str, b: str) -> bool:
    """Retourne True si severity a >= severity b."""
    try:
        return SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b)
    except ValueError:
        return False


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Fichier
    fh = RotatingFileHandler("logs/ids.log", maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def handle_incident(
    incident: Dict,
    cfg,
    iptables_responder: IptablesResponder,
    fail2ban_responder: Fail2BanResponder,
    smtp_alerter: SMTPAlerter,
    webhook_alerter: WebhookAlerter,
    reporter: IncidentReporter,
):
    attack = incident.get("attack_type", "Unknown")
    ip = incident.get("ip")
    severity = incident.get("severity", "LOW").upper()
    desc = incident.get("description", "")

    logging.warning(
        "Incident détecté [%s] IP=%s severity=%s desc=%s",
        attack,
        ip,
        severity,
        desc,
    )

    # Enregistrement du rapport
    path = reporter.save_incident(incident)

    # Alerte mail / webhook si nécessaire
    if severity_ge(severity, cfg.severity_min_email):
        body = (
            f"Attack: {attack}\n"
            f"Severity: {severity}\n"
            f"IP: {ip}\n"
            f"Description: {desc}\n"
            f"Report: {path}\n"
        )
        subject = f"[IDS] {attack} (severity {severity})"
        smtp_alerter.send_alert(subject, body)
        webhook_alerter.send_alert(subject, body)

    # Blocage IP si nécessaire
    if ip and severity_ge(severity, cfg.severity_min_block):
        iptables_responder.block_ip(ip)
        fail2ban_responder.ban_ip(ip)


def main():
    setup_logging()
    logging.info("Démarrage de l'IDS Web (multi-logs)")

    cfg = load_config()

    detector_functions = detectors.load_detectors(cfg)
    if not detector_functions:
        logging.error("Aucun détecteur disponible, arrêt.")
        return

    # Réponse (iptables)
    iptables_responder = IptablesResponder(
        command_template=cfg.iptables_command,
        enabled=cfg.iptables_enabled,
    )

    # Réponse (Fail2Ban)
    fail2ban_responder = Fail2BanResponder(
        jail=cfg.fail2ban_jail,
        command_template=cfg.fail2ban_command,
        enabled=cfg.fail2ban_enabled,
    )

    # Alertes SMTP
    smtp_alerter = SMTPAlerter(
        server=cfg.smtp_server,
        port=cfg.smtp_port,
        from_email=cfg.smtp_from_email,
        to_email=cfg.smtp_to_email,
        username=cfg.smtp_username,
        password=cfg.smtp_password,
        enabled=cfg.smtp_enabled,
    )

    # Alertes Webhook
    webhook_alerter = WebhookAlerter(
        url=cfg.webhook_url,
        enabled=cfg.webhook_enabled,
        timeout_seconds=cfg.webhook_timeout,
        verify_tls=cfg.webhook_verify_tls,
    )

    # Reporter
    reporter = IncidentReporter(cfg.incidents_dir)
    log_sources = cfg.log_sources
    if not log_sources:
        logging.error("Aucune source de log configurée.")
        return

    logging.info(
        "Surveillance des logs (%d): %s",
        len(log_sources),
        ", ".join(f"{name}={path}" for name, path in log_sources.items()),
    )

    try:
        print("  ___ ____  ____")
        print(" |_ _|  _ \\/ ___| ")
        print("  | || | | \\___ \\ ")
        print("  | || |_| |___) | ")
        print(" |___|____/|____/ ")
        print("\n Web IDS en temps réel (multi-logs)\n")

        for source_name, line in iter_logs(log_sources):
            event = build_event_from_source(source_name, line)
            if not event:
                continue

            for detector in detector_functions:
                try:
                    incident = detector(event)
                except Exception as exc:  # pragma: no cover - résilience runtime
                    logging.exception(
                        "Erreur dans le détecteur %s (source=%s): %s",
                        getattr(detector, "__name__", detector.__class__.__name__),
                        source_name,
                        exc,
                    )
                    continue
                if incident:
                    handle_incident(
                        incident,
                        cfg,
                        iptables_responder,
                        fail2ban_responder,
                        smtp_alerter,
                        webhook_alerter,
                        reporter,
                    )

    except KeyboardInterrupt:
        logging.info("Arrêt de l'IDS par l'utilisateur.")


if __name__ == "__main__":
    main()
