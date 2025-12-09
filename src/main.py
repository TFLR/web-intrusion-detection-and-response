import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, List

from config import load_config, SEVERITY_ORDER
from log_watcher import (
    tail_f,
    parse_apache_line,
    build_mysql_event,
)
from detectors import sqli, xss, nikto
from detectors.brute_force import BruteForceDetector
from response.iptables import IptablesResponder
from response.fail2ban import Fail2BanResponder
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
    fh = RotatingFileHandler(
        "logs/ids.log", maxBytes=5 * 1024 * 1024, backupCount=3
    )
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
    logging.info("Démarrage de l'IDS Web (Apache/MySQL)")

    cfg = load_config()

    # Initialisation brute force
    bf_detector = BruteForceDetector(
        threshold=cfg.brute_force_threshold,
        window_seconds=cfg.brute_force_window,
    )

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

    apache_stream = tail_f(cfg.apache_log_path)
    mysql_stream = tail_f(cfg.mysql_log_path)

    try:
        print("  ___ ____  ____")
        print(" |_ _|  _ \\/ ___| ")
        print("  | || | | \\___ \\ ")
        print("  | || |_| |___) | ")
        print(" |___|____/|____/ ")
        print("\n Web IDS en temps réel (Apache + MySQL)\n")

        while True:
            # MySQL → XSS
            mysql_line = next(mysql_stream)
            mysql_event = build_mysql_event(mysql_line)
            incident = xss.detect(mysql_event)
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

            # Apache → SQLi, Nikto, Brute force
            apache_line = next(apache_stream)
            apache_event = parse_apache_line(apache_line)
            if not apache_event:
                continue

            incidents: List[Dict] = []

            inc_sqli = sqli.detect(apache_event)
            if inc_sqli:
                incidents.append(inc_sqli)

            inc_nikto = nikto.detect(apache_event)
            if inc_nikto:
                incidents.append(inc_nikto)

            inc_bf = bf_detector.process_event(apache_event)
            if inc_bf:
                incidents.append(inc_bf)

            for inc in incidents:
                handle_incident(
                    inc,
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
