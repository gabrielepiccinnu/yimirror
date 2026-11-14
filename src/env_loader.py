"""env_loader.py — carica le variabili da tools/yimirror/.env (gitignored)
senza dipendenze extra (niente python-dotenv)."""

from __future__ import annotations

import os
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def load_env() -> None:
    if not _ENV_PATH.exists():
        return
    for line in _ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
