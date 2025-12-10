# Web Intrusion Detection & Response

Petit IDS temps réel pour surveiller les logs web/BDD et réagir (alertes, blocage d'IP, rapports).

## Configuration
- Fichier principal : `config/config.yml`.
- `logs.include_globs` pointe par défaut sur `/var/log/*.log`, `/var/log/*log*`, `/var/log/**/*.log`, `/var/log/**/*.log.*` et `**/syslog*` pour attraper aussi les logs racine (syslog, syslog.1, messages, etc.). Ajustez `logs.exclude_globs` pour filtrer les fichiers indésirables (ex: `*.gz`, `wtmp`). Les noms de source sont inférés automatiquement (apache/mysql déduits du chemin) et suffixés si plusieurs fichiers d'un même service sont présents (`apache`, `apache_1`, ...).
- Les détecteurs sont chargés automatiquement depuis `src/detectors`. Ajoutez un nouveau module avec une fonction `detect(event)` ou une fabrique `build_detector(config)` qui retourne un callable (ou un objet avec `process_event`).
  - Inclus : SQLi, XSS (MySQL), Nikto, brute force Apache, échecs d'auth PostgreSQL.

## Exécution
Installez les dépendances (`pip install -r requirements.txt`) puis lancez `python src/main.py` depuis la racine du projet. Les incidents sont sauvegardés dans `reports/incidents`.
