"""Append-only, hash-chained audit log, one chain per tenant (plus a '_platform' chain).

Each record commits to the previous record's hash, so an edit, deletion or reordering breaks verification
from that point on. The database also refuses UPDATE, DELETE and TRUNCATE on the table, and the service role
has no grant for them. A tenant can export its own chain and verify it independently with verify_records().
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import psycopg

GENESIS = "0" * 64


def _iso(at: datetime) -> str:
    return at.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical(rec: dict[str, Any]) -> bytes:
    body = {
        "tenant": rec["tenant_id"], "seq": rec["seq"], "at": _iso(rec["at"]) if isinstance(rec["at"], datetime)
        else rec["at"], "actor": rec["actor"], "action": rec["action"], "detail": rec["detail"], "prev": rec["prev"],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(rec: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(rec)).hexdigest()


def append(conn: psycopg.Connection, chain: str, actor: str, action: str,
           detail: dict[str, Any] | None = None) -> dict[str, Any]:
    """Append in the caller's transaction, so the record commits or rolls back with the action it describes."""
    # Serialise writers per chain for the rest of this transaction.
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", [f"audit:{chain}"])
    last = conn.execute("SELECT seq, hash FROM audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                        [chain]).fetchone()
    rec: dict[str, Any] = {
        "tenant_id": chain,
        "seq": (last["seq"] + 1) if last else 1,
        "at": datetime.now(timezone.utc),
        "actor": actor,
        "action": action,
        # Round-trip through JSON so what is hashed is exactly what jsonb will hand back.
        "detail": json.loads(json.dumps(detail or {}, default=str)),
        "prev": last["hash"] if last else GENESIS,
    }
    rec["hash"] = digest(rec)
    conn.execute(
        "INSERT INTO audit_log (tenant_id, seq, at, actor, action, detail, prev, hash) "
        "VALUES (%(tenant_id)s, %(seq)s, %(at)s, %(actor)s, %(action)s, %(detail)s, %(prev)s, %(hash)s)",
        {**rec, "detail": psycopg.types.json.Jsonb(rec["detail"])},
    )
    return rec


def records(conn: psycopg.Connection, chain: str, limit: int | None = None,
            newest_first: bool = False) -> list[dict[str, Any]]:
    order = "DESC" if newest_first else "ASC"
    sql = f"SELECT tenant_id, seq, at, actor, action, detail, prev, hash FROM audit_log " \
          f"WHERE tenant_id = %s ORDER BY seq {order}"
    params: list[Any] = [chain]
    if limit is not None:
        sql += " LIMIT %s"
        params.append(limit)
    return list(conn.execute(sql, params).fetchall())


def verify_records(rows: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """(True, None) if the chain is intact from genesis, else (False, first bad seq). Rows oldest first."""
    prev = GENESIS
    for i, rec in enumerate(rows, start=1):
        if rec.get("seq") != i or rec.get("prev") != prev or rec.get("hash") != digest(rec):
            return False, i
        prev = rec["hash"]
    return True, None


def export_line(rec: dict[str, Any]) -> str:
    out = dict(rec)
    out["at"] = _iso(rec["at"]) if isinstance(rec["at"], datetime) else rec["at"]
    return json.dumps(out, sort_keys=True, ensure_ascii=False)
