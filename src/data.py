"""Carga del dataset InSDN vía kagglehub.

Centraliza el acceso al dataset para que notebooks y scripts compartan
la misma ruta sin duplicar lógica de descarga.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

INSDN_SLUG = "muhammadumarjavaid/insdn-dataset-2020"


def _ensure_kaggle_auth() -> None:
    """Carga credenciales de Kaggle desde .env si no están en el entorno.

    Acepta dos formatos:
    - `KAGGLE_API_TOKEN` (token único, soportado por kagglehub >= 0.4.1).
    - `KAGGLE_USERNAME` + `KAGGLE_KEY` (formato clásico).
    """
    load_dotenv()
    has_token = bool(os.environ.get("KAGGLE_API_TOKEN"))
    has_user_key = bool(
        os.environ.get("KAGGLE_USERNAME") and os.environ.get("KAGGLE_KEY")
    )
    if not (has_token or has_user_key):
        raise RuntimeError(
            "Faltan credenciales de Kaggle. Define KAGGLE_API_TOKEN, o bien "
            "KAGGLE_USERNAME y KAGGLE_KEY, en tu .env."
        )


def get_insdn_path() -> Path:
    """Devuelve la ruta local al dataset InSDN, descargándolo si hace falta.

    kagglehub cachea la descarga en ~/.cache/kagglehub/ y devuelve la
    misma ruta en llamadas sucesivas.
    """
    import kagglehub

    _ensure_kaggle_auth()
    path = kagglehub.dataset_download(INSDN_SLUG)
    return Path(path)
