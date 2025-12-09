import subprocess
import logging


class IptablesResponder:
    def __init__(self, command_template: str, enabled: bool = True):
        self.command_template = command_template
        self.enabled = enabled
        self._blacklist = set()

    def block_ip(self, ip: str) -> None:
        if not self.enabled:
            logging.info("IPTables désactivé, aucune action pour %s", ip)
            return

        if ip in self._blacklist:
            logging.debug("IP %s déjà dans la blacklist, on ignore.", ip)
            return

        cmd = self.command_template.format(ip=ip)
        try:
            subprocess.run(cmd, shell=True, check=True)
            self._blacklist.add(ip)
            logging.warning("IP %s bloquée via iptables: %s", ip, cmd)
        except subprocess.CalledProcessError as e:
            logging.error("Erreur iptables pour %s: %s", ip, e)
