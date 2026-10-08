"""Tenant isolation (API and database) and the hash-chained audit log."""
import json

import psycopg
import pytest

from app import audit
from tests.conftest import OWNER_DSN, SUPER, admin, enrol, new_tenant, viewer, who


def test_requests_without_auth_are_refused(client, monkeypatch):
    assert client.get("/tenants").status_code == 401
    monkeypatch.setenv("CRYPTSAT_AUTH", "none")
    assert client.get("/tenants", headers=SUPER).status_code == 401
    assert client.get("/healthz").status_code == 200


def test_only_super_admin_creates_tenants(client, tenant):
    tid, _ = tenant
    r = client.post("/tenants", headers=admin(tid), json={"id": "x-new", "name": "x", "country": "GM"})
    assert r.status_code == 403
    r = client.post("/tenants", headers=SUPER, json={"id": tid, "name": "dup", "country": "SL"})
    assert r.status_code == 409


def test_one_ministry_cannot_see_another(client, fake):
    a, ea = new_tenant(client)
    b, eb = new_tenant(client)
    enrol(client, fake, a, ea, 3)
    enrol(client, fake, b, eb, 2)
    assert len(client.get(f"/tenants/{a}/devices", headers=viewer(a)).json()) == 3
    assert client.get(f"/tenants/{b}/devices", headers=viewer(a)).status_code == 403
    assert client.get(f"/readonly/v1/tenants/{b}/devices", headers=who("p4sgi", f"{a}:reader")).status_code == 403
    listed = {t["id"] for t in client.get("/tenants", headers=viewer(a)).json()}
    assert listed == {a}
    # The refused probe is recorded in B's chain, not A's.
    actions = [r["action"] for r in client.get(f"/tenants/{b}/audit", headers=SUPER).json()]
    assert "access.denied" in actions


def test_row_level_security_holds_even_for_raw_sql(client, database, fake):
    a, ea = new_tenant(client)
    b, eb = new_tenant(client)
    enrol(client, fake, a, ea, 2)
    enrol(client, fake, b, eb, 2)
    with database.tenant(a) as c:
        # Asking explicitly for B's rows still returns nothing.
        assert c.execute("SELECT count(*) AS n FROM devices WHERE tenant_id = %s", [b]).fetchone()["n"] == 0
        assert c.execute("SELECT count(*) AS n FROM audit_log WHERE tenant_id = %s", [b]).fetchone()["n"] == 0
        assert {r["id"] for r in c.execute("SELECT id FROM tenants")} == {a}
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("INSERT INTO devices (tenant_id, id, amapi_name) VALUES (%s, 'x', 'y')", [b])
    with database.tenant(a) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("INSERT INTO tenants (id, name, country) VALUES ('zz-evil', 'x', 'SL')")
    # With no scope at all, nothing is visible.
    with database.pool.connection() as c:
        assert c.execute("SELECT count(*) AS n FROM devices").fetchone()["n"] == 0


def test_tenant_scope_does_not_leak_across_pooled_connections(client, database):
    a, _ = new_tenant(client)
    with database.tenant(a) as c:
        assert c.execute("SELECT current_setting('app.tenant_id', true) AS t").fetchone()["t"] == a
    for _ in range(database.pool.max_size * 2):
        with database.pool.connection() as c:
            assert (c.execute("SELECT current_setting('app.tenant_id', true) AS t").fetchone()["t"] or "") == ""


def test_audit_chain_verifies_and_is_append_only(client, database, tenant):
    tid, _ = tenant
    for _ in range(3):
        client.post(f"/tenants/{tid}/pause", headers=admin(tid), json={"reason": "drill"})
        client.post(f"/tenants/{tid}/resume", headers=admin(tid))
    v = client.get(f"/tenants/{tid}/audit/verify", headers=viewer(tid)).json()
    assert v["ok"] and v["records"] >= 8

    with database.tenant(tid) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    with database.tenant(tid) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("DELETE FROM audit_log WHERE seq = 2")


def test_tampering_by_the_schema_owner_is_detected(client, tenant):
    tid, _ = tenant
    client.post(f"/tenants/{tid}/pause", headers=admin(tid), json={"reason": "drill"})
    client.post(f"/tenants/{tid}/resume", headers=admin(tid))
    # Even the owner is stopped by the trigger; simulate an attacker who disables it.
    with psycopg.connect(OWNER_DSN, autocommit=True) as c:
        # RLS is forced on the owner too: unscoped, it cannot even see the row.
        assert c.execute("UPDATE audit_log SET actor = 'mallory' WHERE tenant_id = %s", [tid]).rowcount == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege), c.transaction():
            c.execute("SELECT set_config('app.tenant_id', %s, true)", [tid])
            c.execute("UPDATE audit_log SET actor = 'mallory' WHERE tenant_id = %s AND seq = 2", [tid])
        with c.transaction():
            c.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only")
            c.execute("SELECT set_config('app.tenant_id', %s, true)", [tid])
            c.execute("UPDATE audit_log SET actor = 'mallory' WHERE tenant_id = %s AND seq = 2", [tid])
            c.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only")
    v = client.get(f"/tenants/{tid}/audit/verify", headers=viewer(tid)).json()
    assert v == {**v, "ok": False, "first_bad_seq": 2}


def test_export_verifies_offline(client, tenant):
    tid, _ = tenant
    client.post(f"/tenants/{tid}/pause", headers=admin(tid), json={"reason": "drill"})
    assert client.get(f"/tenants/{tid}/audit/export", headers=viewer(tid)).status_code == 403
    r = client.get(f"/tenants/{tid}/audit/export", headers=admin(tid))
    assert r.status_code == 200
    rows = [json.loads(line) for line in r.text.splitlines()]
    assert rows and audit.verify_records(rows) == (True, None)
    rows[0]["detail"] = {"forged": True}
    assert audit.verify_records(rows) == (False, 1)


def test_platform_chain(client):
    new_tenant(client)
    v = client.get("/platform/audit/verify", headers=SUPER).json()
    assert v["ok"] and v["records"] >= 1
    assert client.get("/platform/audit/verify", headers=who("x", "sl:admin")).status_code == 403


def test_verify_all_chains(client, database):
    from app.verify_audit import verify_all
    tid, _ = new_tenant(client)
    results = {r["chain"]: r for r in verify_all(database)}
    assert results[tid]["ok"] and results["_platform"]["ok"]
