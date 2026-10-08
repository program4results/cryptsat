"""Apply SQL migrations in order. Runs as the schema owner (CRYPTSAT_DB_OWNER_DSN), never as the service role.

    python -m app.migrate
"""
from __future__ import annotations

import sys
from pathlib import Path

import psycopg

from . import config

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


def migrate(owner_dsn: str) -> list[str]:
    applied: list[str] = []
    with psycopg.connect(owner_dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations "
                     "(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
        done = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.name in done:
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", [path.name])
            applied.append(path.name)
    return applied


def main() -> int:
    dsn = config.db_owner_dsn()
    if not dsn:
        print("CRYPTSAT_DB_OWNER_DSN is not set", file=sys.stderr)
        return 2
    for name in migrate(dsn):
        print(f"applied {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
