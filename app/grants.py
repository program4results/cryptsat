"""Role grants: who may do what. Changed only by super-admins (or, once, by the bootstrap command below),
and every change is written to the platform audit chain and to the affected tenant's chain.

Bootstrap the first super-admin (only works while there is none):
    CRYPTSAT_DB_DSN=... python -m app.grants bootstrap someone@saltracker.example
"""
from __future__ import annotations

import re
import sys
from typing import Any

import psycopg

from . import audit, config
from .db import PLATFORM_CHAIN, Database

ROLES = ("viewer", "operator", "admin", "reader", "super_admin")
_SUBJECT = re.compile(r"^([^@\s]+@[^@\s]+\.[^@\s]+|sub:[\x21-\x7e]{1,255})$")


class GrantError(ValueError):
    pass


def normalise(subject: str, kind: str, tenant_id: str, role: str) -> tuple[str, str, str, str]:
    subject = subject.strip().lower()
    if not _SUBJECT.match(subject):
        raise GrantError("subject must be an email, or sub:<id> for a service identity")
    if kind not in ("human", "service"):
        raise GrantError("kind must be human or service")
    if role not in ROLES:
        raise GrantError(f"role must be one of {ROLES}")
    if (tenant_id == "*") != (role == "super_admin"):
        raise GrantError("super_admin is granted on '*', and '*' only takes super_admin")
    if kind == "service" and role != "reader":
        raise GrantError("service identities can only be readers")
    if kind == "human" and subject.startswith("sub:"):
        raise GrantError("people are granted by verified email")
    return subject, kind, tenant_id, role


def _audit_both(c: psycopg.Connection, actor: str, action: str, detail: dict[str, Any], tenant_id: str) -> None:
    audit.append(c, PLATFORM_CHAIN, actor, action, detail)
    if tenant_id != "*":
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [tenant_id])
        audit.append(c, tenant_id, actor, action, detail)
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [PLATFORM_CHAIN])


def add(c: psycopg.Connection, actor: str, subject: str, kind: str, tenant_id: str, role: str) -> dict[str, Any]:
    """Call inside db.platform()."""
    subject, kind, tenant_id, role = normalise(subject, kind, tenant_id, role)
    if tenant_id != "*" and not c.execute("SELECT 1 FROM tenants WHERE id = %s", [tenant_id]).fetchone():
        raise GrantError("tenant not found")
    other = c.execute("SELECT kind FROM role_grants WHERE subject = %s AND kind <> %s LIMIT 1",
                      [subject, kind]).fetchone()
    if other:
        raise GrantError(f"subject already has {other['kind']} grants; one identity cannot be both")
    row = c.execute("INSERT INTO role_grants (subject, kind, tenant_id, role, granted_by) VALUES (%s,%s,%s,%s,%s) "
                    "ON CONFLICT DO NOTHING RETURNING subject", [subject, kind, tenant_id, role, actor]).fetchone()
    detail = {"subject": subject, "kind": kind, "tenant": tenant_id, "role": role}
    if row:
        _audit_both(c, actor, "grant.add", detail, tenant_id)
    return {**detail, "created": bool(row)}


def revoke(c: psycopg.Connection, actor: str, subject: str, tenant_id: str, role: str) -> dict[str, Any]:
    """Call inside db.platform()."""
    subject = subject.strip().lower()
    if role == "super_admin":
        c.execute("SELECT pg_advisory_xact_lock(hashtextextended('grants:super', 0))")
        n = c.execute("SELECT count(*) AS n FROM role_grants WHERE role = 'super_admin'").fetchone()["n"]
        if n <= 1:
            raise GrantError("cannot revoke the last super-admin")
    row = c.execute("DELETE FROM role_grants WHERE subject = %s AND tenant_id = %s AND role = %s RETURNING kind",
                    [subject, tenant_id, role]).fetchone()
    if not row:
        raise GrantError("no such grant")
    detail = {"subject": subject, "tenant": tenant_id, "role": role}
    _audit_both(c, actor, "grant.revoke", detail, tenant_id)
    return detail


def bootstrap(db: Database, email: str) -> dict[str, Any]:
    with db.platform() as c:
        c.execute("SELECT pg_advisory_xact_lock(hashtextextended('grants:super', 0))")
        if c.execute("SELECT 1 FROM role_grants WHERE role = 'super_admin' LIMIT 1").fetchone():
            raise GrantError("a super-admin already exists; grant further roles through the API")
        return add(c, "bootstrap-cli", email, "human", "*", "super_admin")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "bootstrap":
        print(__doc__, file=sys.stderr)
        return 2
    db = Database(config.db_dsn(), max_size=1)
    db.open()
    try:
        print(bootstrap(db, argv[1]))
    except GrantError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
