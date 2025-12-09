import os
import yaml


DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "config.yml"
)

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Config:
    def __init__(self, data: dict):
        self.data = data or {}

    @property
    def apache_log_path(self) -> str:
        return self.data.get("logs", {}).get("apache", "/var/log/apache2/access.log")

    @property
    def mysql_log_path(self) -> str:
        return self.data.get("logs", {}).get("mysql", "/var/log/mysql/mysql.log")

    @property
    def brute_force_enabled(self) -> bool:
        return self.data.get("detection", {}).get("brute_force", {}).get("enabled", True)

    @property
    def brute_force_threshold(self) -> int:
        return int(
            self.data.get("detection", {})
            .get("brute_force", {})
            .get("requests_threshold", 20)
        )

    @property
    def brute_force_window(self) -> int:
        return int(
            self.data.get("detection", {})
            .get("brute_force", {})
            .get("window_seconds", 2)
        )

    @property
    def iptables_enabled(self) -> bool:
        return self.data.get("response", {}).get("iptables", {}).get("enabled", True)

    @property
    def iptables_command(self) -> str:
        return (
            self.data.get("response", {})
            .get("iptables", {})
            .get("command", "sudo iptables -A INPUT -s {ip} -j DROP")
        )

    @property
    def smtp_enabled(self) -> bool:
        return self.data.get("alerting", {}).get("smtp", {}).get("enabled", False)

    @property
    def smtp_server(self) -> str:
        return self.data.get("alerting", {}).get("smtp", {}).get("server", "localhost")

    @property
    def smtp_port(self) -> int:
        return int(
            self.data.get("alerting", {}).get("smtp", {}).get("port", 25)
        )

    @property
    def smtp_from_email(self) -> str:
        return self.data.get("alerting", {}).get("smtp", {}).get("from_email", "")

    @property
    def smtp_to_email(self) -> str:
        return self.data.get("alerting", {}).get("smtp", {}).get("to_email", "")

    @property
    def smtp_username(self) -> str:
        env_name = (
            self.data.get("alerting", {})
            .get("smtp", {})
            .get("username_env", "IDS_SMTP_USER")
        )
        return os.getenv(env_name, "")

    @property
    def smtp_password(self) -> str:
        env_name = (
            self.data.get("alerting", {})
            .get("smtp", {})
            .get("password_env", "IDS_SMTP_PASSWORD")
        )
        return os.getenv(env_name, "")

    @property
    def incidents_dir(self) -> str:
        return (
            self.data.get("reporting", {})
            .get("incidents_dir", "./reports/incidents")
        )

    @property
    def severity_min_email(self) -> str:
        v = (
            self.data.get("reporting", {})
            .get("severity_min_email", "MEDIUM")
        ).upper()
        return v if v in SEVERITY_ORDER else "MEDIUM"

    @property
    def severity_min_block(self) -> str:
        v = (
            self.data.get("reporting", {})
            .get("severity_min_block", "HIGH")
        ).upper()
        return v if v in SEVERITY_ORDER else "HIGH"
    
    @property
    def fail2ban_enabled(self) -> bool:
        return self.data.get("response", {}).get("fail2ban", {}).get("enabled", False)

    @property
    def fail2ban_jail(self) -> str:
        return (
            self.data.get("response", {})
            .get("fail2ban", {})
            .get("jail", "")
        )

    @property
    def fail2ban_command(self) -> str:
        return (
            self.data.get("response", {})
            .get("fail2ban", {})
            .get("command", "sudo fail2ban-client set {jail} banip {ip}")
        )

    @property
    def webhook_enabled(self) -> bool:
        return self.data.get("alerting", {}).get("webhook", {}).get("enabled", False)

    @property
    def webhook_url(self) -> str:
        return self.data.get("alerting", {}).get("webhook", {}).get("url", "")

    @property
    def webhook_timeout(self) -> int:
        return int(
            self.data.get("alerting", {})
            .get("webhook", {})
            .get("timeout_seconds", 5)
        )

    @property
    def webhook_verify_tls(self) -> bool:
        return bool(
            self.data.get("alerting", {})
            .get("webhook", {})
            .get("verify_tls", True)
        )


def load_config(path: str = None) -> Config:
    """Charge la config YAML et retourne un objet Config."""
    path = path or DEFAULT_CONFIG_PATH
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return Config(data)
