"""Rollout, dry run, kill switch, commands, enrolment and protected devices."""
from app import rings
from tests.conftest import SUPER, admin, enrol, new_tenant, operator, viewer, who


def baseline(client, tid, h=None):
    r = client.post(f"/tenants/{tid}/policies/baseline/versions", headers=h or admin(tid), json={"template": "baseline"})
    assert r.status_code == 201, r.text
    return r.json()["version"]


# ---------------------------------------------------------------- policies
def test_policy_versions_are_validated_and_numbered(client, tenant):
    tid, _ = tenant
    assert baseline(client, tid) == 1
    assert baseline(client, tid) == 2
    r = client.post(f"/tenants/{tid}/policies/baseline/versions", headers=admin(tid),
                    json={"body": {"keyguardDisabled": True}})
    assert r.status_code == 422
    r = client.post(f"/tenants/{tid}/policies/baseline/versions", headers=admin(tid), json={"body": {"wipe": 1}})
    assert r.status_code == 422
    r = client.post(f"/tenants/{tid}/policies/baseline/versions", headers=operator(tid), json={"template": "baseline"})
    assert r.status_code == 403
    assert client.get(f"/tenants/{tid}/policies", headers=viewer(tid)).json()[0]["latest"] == 2


def test_apply_needs_a_dry_run_and_touches_only_its_devices(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 40)
    v = baseline(client, tid)
    assert client.put(f"/tenants/{tid}/pilot-devices", headers=admin(tid), json={"device_ids": ids[:2]}).status_code == 200

    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()
    assert dr["stage"] == "pilot"
    assert sorted(d["device_id"] for d in dr["would_touch"]) == ids[:2]
    assert dr["skipped"]["outside_ring"] == 38

    # A device enrolled after the dry run is not touched by it.
    fake.add_device(ent, "late", serial="SN-late")
    client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid))
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=operator(tid)).status_code == 403
    r = client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid))
    assert r.status_code == 200, r.text
    assert sorted(r.json()["applied_to"]) == ids[:2]
    assert sorted(c[1][0].rsplit("/", 1)[1] for c in fake.calls if c[0] == "set_device_policy") == ids[:2]
    # Cannot be replayed.
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid)).status_code == 409
    # Unknown or malformed dry run ids are 404.
    assert client.post(f"/tenants/{tid}/dry-runs/not-a-uuid/apply", headers=admin(tid)).status_code == 404


def test_stage_change_invalidates_dry_run_and_rings_advance_one_at_a_time(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 60)
    v = baseline(client, tid)
    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()
    assert "stage is pilot but no pilot devices are set" in dr["warnings"]

    assert client.post(f"/tenants/{tid}/stage", headers=admin(tid), json={"stage": "r25", "check_note": "x" * 20}).status_code == 409
    assert client.post(f"/tenants/{tid}/stage", headers=admin(tid), json={"stage": "r5"}).status_code == 422
    r = client.post(f"/tenants/{tid}/stage", headers=admin(tid),
                    json={"stage": "r5", "check_note": "pilot tablets enrolled and reporting"})
    assert r.status_code == 200 and r.json()["stage"] == "r5"
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid)).status_code == 409

    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()
    expected = sorted(i for i in ids if rings.bucket(tid, i) < 5)
    assert sorted(d["device_id"] for d in dr["would_touch"]) == expected
    # Going back a ring needs no note.
    assert client.post(f"/tenants/{tid}/stage", headers=admin(tid), json={"stage": "pilot"}).status_code == 200


def test_google_failure_mid_apply_is_audited(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 3)
    v = baseline(client, tid)
    client.put(f"/tenants/{tid}/pilot-devices", headers=admin(tid), json={"device_ids": ids})
    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()
    fake.fail_on.add("set_device_policy")
    r = client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid))
    assert r.status_code == 502
    last = client.get(f"/tenants/{tid}/audit?limit=1", headers=viewer(tid)).json()[0]
    assert last["action"] == "policy.apply.failed" and last["detail"]["devices_changed_at_google"] == []
    # The dry run was not consumed, so it can be retried once Google recovers.
    fake.fail_on.clear()
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid)).status_code == 200


# ---------------------------------------------------------------- kill switch
def test_pause_blocks_every_outbound_action_but_not_reads(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 3)
    v = baseline(client, tid)
    client.put(f"/tenants/{tid}/pilot-devices", headers=admin(tid), json={"device_ids": ids})
    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()

    assert client.post(f"/tenants/{tid}/pause", headers=operator(tid), json={"reason": "bad report"}).status_code == 200
    calls = len(fake.calls)
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid)).status_code == 409
    assert client.post(f"/tenants/{tid}/devices/{ids[0]}/commands", headers=SUPER, json={"type": "LOCK"}).status_code == 409
    tok = {"policy_name": "baseline", "version": v, "attest_new_or_factory_reset": True}
    assert client.post(f"/tenants/{tid}/enrolment-tokens", headers=admin(tid), json=tok).status_code == 409
    assert client.post(f"/tenants/{tid}/stage", headers=admin(tid),
                       json={"stage": "r5", "check_note": "x" * 20}).status_code == 409
    assert len(fake.calls) == calls          # nothing reached Google
    assert client.get(f"/tenants/{tid}/devices", headers=viewer(tid)).status_code == 200
    assert client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid)).status_code == 200

    assert client.post(f"/tenants/{tid}/resume", headers=operator(tid)).status_code == 403
    assert client.post(f"/tenants/{tid}/resume", headers=admin(tid)).status_code == 200
    assert client.post(f"/tenants/{tid}/dry-runs/{dr['dry_run_id']}/apply", headers=admin(tid)).status_code == 200


def test_tenant_without_enterprise_cannot_push(client):
    tid, _ = new_tenant(client, enterprise=False)
    v = baseline(client, tid)
    tok = {"policy_name": "baseline", "version": v, "attest_new_or_factory_reset": True}
    assert client.post(f"/tenants/{tid}/enrolment-tokens", headers=admin(tid), json=tok).status_code == 409
    assert client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid)).status_code == 409


# ---------------------------------------------------------------- commands
def test_commands_are_super_admin_only_and_never_wipe(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 2)
    url = f"/tenants/{tid}/devices/{ids[0]}/commands"
    assert client.post(url, headers=admin(tid), json={"type": "LOCK"}).status_code == 403
    assert client.post(url, headers=viewer(tid), json={"type": "LOCK"}).status_code == 403
    for t in ("WIPE", "RESET_PASSWORD", "RELINQUISH_OWNERSHIP"):
        assert client.post(url, headers=SUPER, json={"type": t}).status_code == 422
    assert not any(c[0] == "issue_command" for c in fake.calls)
    assert client.post(url, headers=SUPER, json={"type": "LOCK"}).status_code == 201
    assert client.post(url, headers=SUPER, json={"type": "REBOOT"}).status_code == 201
    assert [c[1][1] for c in fake.calls if c[0] == "issue_command"] == ["LOCK", "REBOOT"]
    actions = [r["action"] for r in client.get(f"/tenants/{tid}/audit?limit=20", headers=viewer(tid)).json()]
    assert actions.count("device.command") == 2 and actions.count("device.command.refused") == 3
    assert client.post(f"/tenants/{tid}/devices/nope/commands", headers=SUPER, json={"type": "LOCK"}).status_code == 404


def test_database_rejects_wipe_even_if_the_api_did_not(client, database, fake, tenant):
    import psycopg
    import pytest
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 1)
    with database.tenant(tid) as c:
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("INSERT INTO commands (tenant_id, device_id, type, requested_by) VALUES (%s, %s, 'WIPE', 'x')",
                      [tid, ids[0]])


# ---------------------------------------------------------------- protected field tablets
def test_protected_devices_are_flagged_and_never_touched(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 3)
    r = client.post(f"/tenants/{tid}/protected-serials", headers=admin(tid),
                    json={"serials": ["FIELD-0001"], "note": "existing RustDesk fleet"})
    assert r.status_code == 201
    # A field tablet turns up enrolled.
    fake.add_device(ent, "field1", serial="FIELD-0001")
    r = client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid)).json()
    assert r["protected_flagged"] == [{"device_id": "field1", "serial": "FIELD-0001"}]
    alerts = [a for a in client.get(f"/tenants/{tid}/audit", headers=viewer(tid)).json()
              if a["action"] == "alert.protected_device_enrolled"]
    assert len(alerts) == 1

    assert client.post(f"/tenants/{tid}/devices/field1/commands", headers=SUPER, json={"type": "LOCK"}).status_code == 409
    assert client.put(f"/tenants/{tid}/pilot-devices", headers=admin(tid),
                      json={"device_ids": ["field1"]}).status_code == 409
    for stage, note in (("r5", "checked"), ("r25", "checked"), ("r100", "checked")):
        client.post(f"/tenants/{tid}/stage", headers=admin(tid), json={"stage": stage, "check_note": note * 3})
    v = baseline(client, tid)
    dr = client.post(f"/tenants/{tid}/policies/baseline/versions/{v}/dry-run", headers=operator(tid)).json()
    assert dr["skipped"]["protected"] == 1
    assert sorted(d["device_id"] for d in dr["would_touch"]) == ids
    # Re-syncing does not raise the alert twice.
    client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid))
    alerts = [a for a in client.get(f"/tenants/{tid}/audit", headers=viewer(tid)).json()
              if a["action"] == "alert.protected_device_enrolled"]
    assert len(alerts) == 1


def test_devices_gone_from_google_are_marked(client, fake, tenant):
    tid, ent = tenant
    ids = enrol(client, fake, tid, ent, 2)
    del fake.devices[ent][f"{ent}/devices/{ids[0]}"]
    assert client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid)).json()["not_listed"] == 1
    states = {d["id"]: d["state"] for d in client.get(f"/tenants/{tid}/devices", headers=viewer(tid)).json()}
    assert states == {ids[0]: "NOT_LISTED", ids[1]: "ACTIVE"}


# ---------------------------------------------------------------- enrolment
def test_enrolment_token_needs_attestation_and_is_never_stored(client, database, fake, tenant):
    tid, _ = tenant
    v = baseline(client, tid)
    body = {"policy_name": "baseline", "version": v, "ttl_hours": 48, "attest_new_or_factory_reset": False}
    assert client.post(f"/tenants/{tid}/enrolment-tokens", headers=admin(tid), json=body).status_code == 422
    body["attest_new_or_factory_reset"] = True
    assert client.post(f"/tenants/{tid}/enrolment-tokens", headers=operator(tid), json=body).status_code == 403
    r = client.post(f"/tenants/{tid}/enrolment-tokens", headers=admin(tid), json=body)
    assert r.status_code == 201, r.text
    value = r.json()["value"]
    assert r.json()["policy"].endswith("/policies/baseline-v1") and r.json()["qr_code"]
    assert fake.tokens[0]["duration"] == f"{48 * 3600}s"
    with database.tenant(tid) as c:
        row = c.execute("SELECT * FROM enrolment_tokens").fetchone()
        assert value not in str(row)
        log = str(c.execute("SELECT detail FROM audit_log").fetchall())
        assert value not in log
    assert client.post(f"/tenants/{tid}/enrolment-tokens", headers=admin(tid),
                       json={**body, "version": 99}).status_code == 404


def test_without_google_configured_calls_fail_closed(database, tenant):
    from fastapi.testclient import TestClient

    from app.amapi import UnconfiguredAmapi
    from app.main import create_app
    tid, _ = tenant
    c = TestClient(create_app(db=database, amapi_client=UnconfiguredAmapi()))
    assert c.post(f"/tenants/{tid}/devices/sync", headers=operator(tid)).status_code == 503
    assert c.get(f"/tenants/{tid}/devices", headers=viewer(tid)).status_code == 200


# ---------------------------------------------------------------- read-only adapter for sl.p4sgi
def test_readonly_adapter(client, fake, tenant):
    tid, ent = tenant
    enrol(client, fake, tid, ent, 3)
    reader = who("p4sgi-adapter", f"{tid}:reader")
    r = client.get(f"/readonly/v1/tenants/{tid}/devices", headers=reader)
    assert r.status_code == 200
    body = r.json()
    assert body["counts"]["total"] == 3 and body["counts"]["active"] == 3
    assert {"id", "serial", "state", "policy_compliant", "last_status_at"} <= set(body["devices"][0])
    # The reader role can do nothing else.
    assert client.get(f"/tenants/{tid}/devices", headers=reader).status_code == 403
    assert client.post(f"/tenants/{tid}/pause", headers=reader, json={"reason": "nope"}).status_code == 403
    assert client.get("/tenants", headers=reader).json() == []
