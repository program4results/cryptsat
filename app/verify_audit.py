"""Verify every audit chain (each tenant plus the platform chain). Exit code 0 if all are intact, 1 if any
chain is broken. Meant for a scheduled job whose failure raises an alert.

    CRYPTSAT_DB_DSN=... python -m app.verify_audit
"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import audit, config
from .db import PLATFORM_CHAIN, Database


def verify_all(db: Database) -> list[dict[str, Any]]:
    with db.platform() as c:
        tenant_ids = [r["id"] for r in c.execute("SELECT id FROM tenants ORDER BY id")]
        rows = audit.records(c, PLATFORM_CHAIN)
    results = [{"chain": PLATFORM_CHAIN, **_check(rows)}]
    for tid in tenant_ids:
        with db.tenant(tid) as c:
            results.append({"chain": tid, **_check(audit.records(c, tid))})
    return results


def _check(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ok, bad = audit.verify_records(rows)
    return {"ok": ok, "first_bad_seq": bad, "records": len(rows), "head": rows[-1]["hash"] if rows else None}


def main() -> int:
    db = Database(config.db_dsn(), max_size=1)
    db.open()
    try:
        results = verify_all(db)
    finally:
        db.close()
    for r in results:
        print(json.dumps(r))
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
