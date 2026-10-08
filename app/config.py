"""Settings from environment. Fail closed: anything not explicitly enabled is off."""
from __future__ import annotations

import os
from pathlib import Path


def env() -> str:
    return os.getenv("CRYPTSAT_ENV", "production").strip().lower()


def flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def data_dir() -> Path:
    return Path(os.getenv("DATA_DIR", "./data"))


def amapi_mode() -> str:
    """'fake' (tests/dev), or 'google' (not implemented yet: needs Google quota and credentials)."""
    return os.getenv("CRYPTSAT_AMAPI", "none").strip().lower()
