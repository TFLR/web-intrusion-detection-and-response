import logging
import subprocess


class Fail2BanResponder:
    """
    Intégration simple avec fail2ban via fail2ban-client.
    Commande typique :
      sudo fail2ban-client set <jail> banip <ip>
    """

    def __init__(
        self,
        jail: str,
        command_template: str = "sudo fail2ban-client set {jail} banip {ip}",
        enabled: bool = True,
    ):
        self.jail = jail
        self.command_template = command_template
        self.enabled = enabled
        self._blacklist = set()

    def ban_ip(self, ip: str) -> None:
        if not self.enabled:
            logging.debug("Fail2Ban désactivé, aucune action pour %s", ip)
            return

        if not self.jail:
            logging.warning("Aucun jail Fail2Ban configuré, ban ignoré pour %s", ip)
            return

        if ip in self._blacklist:
            logging.debug("IP %s déjà bannie via Fail2Ban, on ignore.", ip)
            return

        cmd = self.command_template.format(jail=self.jail, ip=ip)

        try:
            subprocess.run(cmd, shell=True, check=True)
            self._blacklist.add(ip)
            logging.warning("IP %s bannie via Fail2Ban (jail=%s)", ip, self.jail)
        except subprocess.CalledProcessError as e:
            logging.error("Erreur Fail2Ban pour %s: %s", ip, e)
