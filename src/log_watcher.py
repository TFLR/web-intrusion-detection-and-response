import logging
import os
import time
from datetime import datetime
import re
from typing import Dict, Generator, Optional, Tuple


APACHE_REGEX = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"  # IP
    r"\S+\s+\S+\s+"                         # ident/user (ignored)
    r"\[(?P<ts>[^\]]+)\]\s+"                # timestamp
    r"\"(?P<method>[A-Z]+)\s+(?P<path>[^\s\"]+)\s+[^\"]*\"\s+"  # request line
    r"(?P<status>\d{3})\s+"                   # status code
    r"(?P<size>\S+)"                          # response size
    r"(?:\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<user_agent>[^\"]*)\")?"  # optional ref/ua
)


def tail_f(path: str) -> Generator[str, None, None]:
    """Émule un tail -f sur un chemin de fichier."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def iter_logs(
    sources: Dict[str, str], poll_interval: float = 0.5
) -> Generator[Tuple[str, str], None, None]:
    """Iterate over multiple log files without bloquer sur un seul fichier."""
    handles = {}
    for name, path in sources.items():
        if not os.path.isfile(path):
            logging.warning("Fichier de log introuvable pour %s: %s", name, path)
            continue
        fh = open(path, "r", encoding="utf-8", errors="ignore")
        fh.seek(0, os.SEEK_END)
        handles[name] = fh

    if not handles:
        logging.error("Aucun fichier de log disponible, arrêt du watcher.")
        return

    try:
        while True:
            has_lines = False
            for name, fh in handles.items():
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    has_lines = True
                    yield name, line
            if not has_lines:
                time.sleep(poll_interval)
    finally:
        for fh in handles.values():
            fh.close()


def parse_apache_line(line: str) -> Optional[Dict]:
    match = APACHE_REGEX.search(line)
    if not match:
        return None
    ip = match.group("ip")
    ts_str = match.group("ts")
    try:
        ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None
    return {
        "source": "apache",
        "ip": ip,
        "timestamp": ts,
        "raw": line,
        "method": match.group("method"),
        "path": match.group("path"),
        "status": match.group("status"),
        "size": match.group("size"),
        "referrer": match.group("referrer"),
        "user_agent": match.group("user_agent"),
    }


def build_mysql_event(line: str) -> Dict:
    # On ne parse pas tout, mais on encapsule l'info brute
    return {
        "source": "mysql",
        "ip": None,
        "timestamp": datetime.utcnow(),
        "raw": line,
    }


def build_event_from_source(source: str, line: str) -> Optional[Dict]:
    """Construit un événement standardisé à partir d'un nom de source et d'une ligne brute."""
    if source.startswith("apache"):
        parsed = parse_apache_line(line)
        if parsed:
            return parsed
        # Fallback: on garde la ligne brute pour les autres détecteurs
        return {
            "source": "apache",
            "ip": None,
            "timestamp": datetime.utcnow(),
            "raw": line,
        }

    if source.startswith("mysql"):
        return build_mysql_event(line)

    return {
        "source": source,
        "ip": None,
        "timestamp": datetime.utcnow(),
        "raw": line,
    }
