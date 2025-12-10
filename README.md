# Web Intrusion Detection & Response

Petit IDS temps réel pour surveiller les logs web/BDD et réagir (alertes, blocage d'IP, rapports).

## Configuration
- Fichier principal : `config/config.yml`.
- `logs.include_globs` pointe par défaut sur `/var/log/**/*.log` pour couvrir l'ensemble des logs sous `/var/log`. Ajustez `logs.exclude_globs` pour filtrer les fichiers indésirables (ex: `*.gz`, `wtmp`).
- Conservez des entrées nommées (ex: `logs.apache`, `logs.mysql`) pour bénéficier d'un parsing adapté et de noms de source lisibles.
- Les détecteurs sont chargés automatiquement depuis `src/detectors`. Ajoutez un nouveau module avec une fonction `detect(event)` ou une fabrique `build_detector(config)` qui retourne un callable (ou un objet avec `process_event`).

## Exécution
Installez les dépendances (`pip install -r requirements.txt`) puis lancez `python src/main.py` depuis la racine du projet. Les incidents sont sauvegardés dans `reports/incidents`.
