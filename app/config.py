"""Settings from environment. Fail closed: anything not explicitly enabled is off."""
from __future__ import annotations

import os

DEV_ENVS = {"dev", "test"}


def env() -> str:
    return os.getenv("CRYPTSAT_ENV", "production").strip().lower()


def flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def amapi_mode() -> str:
    """'none' (default: every Google call fails with 503), 'fake' (tests/dev only), or later 'google'."""
    return os.getenv("CRYPTSAT_AMAPI", "none").strip().lower()


def auth_mode() -> str:
    """'none' (default: every request is 401 until OIDC is wired), or 'dev' (header principal, dev/test only)."""
    return os.getenv("CRYPTSAT_AUTH", "none").strip().lower()


def db_dsn() -> str:
    """DSN for the service role (cryptsat_app). Row-level security applies to this role."""
    return os.getenv("CRYPTSAT_DB_DSN", "")


def db_owner_dsn() -> str:
    """DSN for the schema owner. Used only by migrations."""
    return os.getenv("CRYPTSAT_DB_OWNER_DSN", "")


def dry_run_max_age_hours() -> int:
    return int(os.getenv("CRYPTSAT_DRY_RUN_MAX_AGE_HOURS", "24"))


def check() -> None:
    """Refuse to start with settings that are only safe in development."""
    if env() not in DEV_ENVS:
        if auth_mode() == "dev":
            raise RuntimeError("CRYPTSAT_AUTH=dev is only allowed when CRYPTSAT_ENV is dev or test")
        if amapi_mode() == "fake":
            raise RuntimeError("CRYPTSAT_AMAPI=fake is only allowed when CRYPTSAT_ENV is dev or test")
    if amapi_mode() not in ("none", "fake"):
        raise RuntimeError(f"CRYPTSAT_AMAPI={amapi_mode()} is not implemented (real client waits for Google quota)")
