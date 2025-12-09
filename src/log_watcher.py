import os
import time
from datetime import datetime
import re
from typing import Generator, Dict, Optional


APACHE_REGEX = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<ts>\d+/\w+/\d+:\d+:\d+:\d+)"
)


def tail_f(path: str) -> Generator[str, None, None]:
    """Émule un tail -f sur un chemin de fichier."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def parse_apache_line(line: str) -> Optional[Dict]:
    match = APACHE_REGEX.search(line)
    if not match:
        return None
    ip = match.group("ip")
    ts_str = match.group("ts")
    ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
    return {
        "source": "apache",
        "ip": ip,
        "timestamp": ts,
        "raw": line,
    }


def build_mysql_event(line: str) -> Dict:
    # On ne parse pas tout, mais on encapsule l'info brute
    return {
        "source": "mysql",
        "ip": None,
        "timestamp": datetime.utcnow(),
        "raw": line,
    }
