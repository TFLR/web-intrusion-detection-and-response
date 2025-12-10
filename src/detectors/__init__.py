"""Gestion dynamique des détecteurs présents dans le package."""

import importlib
import logging
import pkgutil
from typing import Any, Callable, Dict, List, Optional

DetectorFunc = Callable[[Dict], Optional[Dict]]


def _as_detector(candidate: Any) -> Optional[DetectorFunc]:
    if candidate is None:
        return None
    if callable(candidate):
        return candidate
    process = getattr(candidate, "process_event", None)
    if callable(process):
        return process
    return None


def load_detectors(config=None) -> List[DetectorFunc]:
    """Charge tous les modules de détecteurs et retourne les callables prêts à l'emploi."""
    detectors: List[DetectorFunc] = []
    seen = set()

    for _, module_name, _ in pkgutil.iter_modules(__path__):
        if module_name.startswith("_"):
            continue

        try:
            module = importlib.import_module(f"{__name__}.{module_name}")
        except Exception as exc:
            logging.error("Impossible de charger le module de détecteur %s: %s", module_name, exc)
            continue

        candidate: Any = None

        if hasattr(module, "build_detector") and callable(module.build_detector):
            try:
                candidate = module.build_detector(config)  # type: ignore[attr-defined]
            except Exception as exc:
                logging.error(
                    "Erreur lors de l'initialisation du détecteur %s: %s",
                    module_name,
                    exc,
                )
                continue
        elif hasattr(module, "get_detector") and callable(module.get_detector):
            candidate = module.get_detector()  # type: ignore[attr-defined]
        elif hasattr(module, "detect") and callable(module.detect):
            candidate = module.detect  # type: ignore[attr-defined]
        elif hasattr(module, "Detector") and callable(getattr(module, "Detector")):
            try:
                candidate = module.Detector()  # type: ignore[attr-defined]
            except Exception as exc:
                logging.error(
                    "Impossible d'instancier le détecteur %s: %s",
                    module_name,
                    exc,
                )
                continue

        detector_fn = _as_detector(candidate)
        if detector_fn:
            if id(detector_fn) in seen:
                continue
            seen.add(id(detector_fn))
            detectors.append(detector_fn)
        else:
            logging.debug("Aucun détecteur callable trouvé dans %s", module_name)

    return detectors


__all__ = ["load_detectors", "DetectorFunc"]
