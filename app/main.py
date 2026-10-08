"""CryptSat MDM HTTP API (FastAPI).

Guardrails enforced here (and, where possible, again in the database):
  - Every request is authenticated (OIDC pending: default mode refuses everything) and authorised per tenant.
  - Every query runs in a transaction scoped to one tenant, so row-level security isolates ministries.
  - Every state change writes to that tenant's hash-chained audit log in the same transaction.
  - A paused tenant gets no policy push, enrolment token or command. Reads and sync still work.
  - A policy reaches devices only through a dry run, and only the devices that dry run listed.
  - Commands are LOCK and REBOOT only, super-admin only. There is no wipe.
  - Devices whose serial is on the protected list (the existing field fleet) are never touched.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field, model_validator

from . import VERSION, amapi, audit, config, policy, rings
from .auth import Principal, current_principal
from .db import PLATFORM_CHAIN, Database

TenantId = Field(pattern=r"^[a-z][a-z0-9-]{1,30}$")
PolicyName = Field(pattern=r"^[a-z][a-z0-9-]{1,40}$")


# ---------------------------------------------------------------- request bodies
class TenantIn(BaseModel):
    id: str = TenantId
    name: str = Field(min_length=1, max_length=200)
    country: str = Field(pattern=r"^[A-Z]{2}$")
    region: str = Field(default="", max_length=64)


class EnterpriseIn(BaseModel):
    enterprise: str = Field(pattern=r"^enterprises/[A-Za-z0-9_-]+$")


class PauseIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class StageIn(BaseModel):
    stage: Literal["pilot", "r5", "r25", "r100"]
    check_note: str = Field(default="", max_length=2000)


class PilotIn(BaseModel):
    device_ids: list[str] = Field(max_length=10)


class ProtectedIn(BaseModel):
    serials: list[str] = Field(min_length=1, max_length=500)
    note: str = Field(default="", max_length=500)


class PolicyVersionIn(BaseModel):
    template: str | None = None
    body: dict[str, Any] | None = None
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def one_source(self) -> "PolicyVersionIn":
        if (self.template is None) == (self.body is None):
            raise ValueError("give exactly one of template or body")
        return self


class TokenIn(BaseModel):
    policy_name: str = PolicyName
    version: int = Field(gt=0)
    ttl_hours: int = Field(default=24, ge=1, le=24 * 30)
    one_time_only: bool = False
    attest_new_or_factory_reset: bool = Field(
        description="Operator confirms every tablet using this token is new or factory-reset, "
                    "and none is one of the existing field tablets.")


class CommandIn(BaseModel):
    type: str = Field(max_length=40)


# ---------------------------------------------------------------- dependencies and helpers
def get_db(request: Request) -> Database:
    return request.app.state.db


def get_amapi(request: Request) -> amapi.AmapiClient:
    return request.app.state.amapi


def now() -> datetime:
    return datetime.now(timezone.utc)


def load_tenant(c: psycopg.Connection, tid: str) -> dict[str, Any]:
    t = c.execute("SELECT * FROM tenants WHERE id = %s", [tid]).fetchone()
    if not t:
        raise HTTPException(404, "tenant not found")
    return t


def require_active(t: dict[str, Any]) -> None:
    if t["paused"]:
        raise HTTPException(409, f"tenant is paused: {t['paused_reason']}")
    if not t["enterprise"]:
        raise HTTPException(409, "tenant has no AMAPI enterprise bound yet")


def authorise(db: Database, p: Principal, tid: str, role: str) -> None:
    if p.can(tid, role):
        return
    # Record refused attempts against an existing tenant. The response is 403 either way, so it reveals nothing.
    with db.tenant(tid) as c:
        if c.execute("SELECT 1 FROM tenants WHERE id = %s", [tid]).fetchone():
            audit.append(c, tid, p.subject, "access.denied", {"needed": role})
    raise HTTPException(403, "not allowed for this tenant")


def require_super(db: Database, p: Principal, action: str) -> None:
    if p.is_super:
        return
    with db.platform() as c:
        audit.append(c, PLATFORM_CHAIN, p.subject, "access.denied", {"needed": "super_admin", "action": action})
    raise HTTPException(403, "super-admin only")


def record_failure(db: Database, tid: str, actor: str, action: str, detail: dict[str, Any], err: Exception) -> None:
    with db.tenant(tid) as c:
        audit.append(c, tid, actor, f"{action}.failed", {**detail, "error": type(err).__name__})


def dt(v: Any) -> Any:
    return v.astimezone(timezone.utc).isoformat() if isinstance(v, datetime) else v


def clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: dt(v) for k, v in row.items()}


# ---------------------------------------------------------------- app
def create_app(db: Database | None = None, amapi_client: amapi.AmapiClient | None = None) -> FastAPI:
    config.check()
    own_db = db is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if own_db:
            app.state.db.open()
        yield
        if own_db:
            app.state.db.close()

    app = FastAPI(title="CryptSat MDM", version=VERSION, lifespan=lifespan)
    app.state.db = db or Database(config.db_dsn())
    app.state.amapi = amapi_client or amapi.make_client(config.amapi_mode())

    @app.exception_handler(amapi.NotConfigured)
    async def _not_configured(_: Request, exc: amapi.NotConfigured) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=503)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "version": VERSION}

    # ------------------------------------------------------------ tenants
    @app.post("/tenants", status_code=201)
    def create_tenant(body: TenantIn, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        require_super(db, p, "tenant.create")
        try:
            with db.platform() as c:
                c.execute("INSERT INTO tenants (id, name, country, region) VALUES (%s, %s, %s, %s)",
                          [body.id, body.name, body.country, body.region])
                audit.append(c, PLATFORM_CHAIN, p.subject, "tenant.create", body.model_dump())
                c.execute("SELECT set_config('app.tenant_id', %s, true)", [body.id])
                audit.append(c, body.id, p.subject, "tenant.create", body.model_dump())
                return clean(load_tenant(c, body.id))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "tenant exists") from None

    @app.get("/tenants")
    def list_tenants(p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        if p.is_super:
            with db.platform() as c:
                return [clean(r) for r in c.execute("SELECT * FROM tenants ORDER BY id")]
        out = []
        for tid in p.tenant_ids():
            if p.level(tid) == 0:
                continue   # reader-only principals use /readonly
            with db.tenant(tid) as c:
                row = c.execute("SELECT * FROM tenants WHERE id = %s", [tid]).fetchone()
                if row:
                    out.append(clean(row))
        return out

    @app.get("/tenants/{tid}")
    def get_tenant(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            t = clean(load_tenant(c, tid))
            t["pilot_devices"] = [r["device_id"] for r in
                                  c.execute("SELECT device_id FROM pilot_devices ORDER BY device_id")]
            return t

    @app.post("/tenants/{tid}/enterprise")
    def bind_enterprise(tid: str, body: EnterpriseIn, p: Principal = Depends(current_principal),
                        db: Database = Depends(get_db)):
        require_super(db, p, "tenant.enterprise.bind")
        try:
            with db.tenant(tid) as c:
                t = load_tenant(c, tid)
                if t["enterprise"]:
                    raise HTTPException(409, "enterprise already bound; rebinding is not supported")
                c.execute("UPDATE tenants SET enterprise = %s WHERE id = %s", [body.enterprise, tid])
                audit.append(c, tid, p.subject, "tenant.enterprise.bind", {"enterprise": body.enterprise})
                return clean(load_tenant(c, tid))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "enterprise is bound to another tenant") from None

    @app.post("/tenants/{tid}/pause")
    def pause(tid: str, body: PauseIn, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        # Operators may pull the kill switch; only admins may release it.
        authorise(db, p, tid, "operator")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            c.execute("UPDATE tenants SET paused = true, paused_reason = %s WHERE id = %s", [body.reason, tid])
            audit.append(c, tid, p.subject, "tenant.pause", {"reason": body.reason})
            return clean(load_tenant(c, tid))

    @app.post("/tenants/{tid}/resume")
    def resume(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            c.execute("UPDATE tenants SET paused = false, paused_reason = NULL WHERE id = %s", [tid])
            audit.append(c, tid, p.subject, "tenant.resume", {})
            return clean(load_tenant(c, tid))

    @app.post("/tenants/{tid}/stage")
    def set_stage(tid: str, body: StageIn, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        with db.tenant(tid) as c:
            t = load_tenant(c, tid)
            if body.stage == t["stage"]:
                return clean(t)
            if rings.is_forward(t["stage"], body.stage):
                if t["paused"]:
                    raise HTTPException(409, "tenant is paused; resume before advancing a ring")
                if body.stage != rings.next_stage(t["stage"]):
                    raise HTTPException(409, f"advance one ring at a time: next is {rings.next_stage(t['stage'])}")
                if len(body.check_note.strip()) < 10:
                    raise HTTPException(422, "advancing a ring needs a check_note describing the manual check "
                                             "of enrolment success and device status")
            c.execute("UPDATE tenants SET stage = %s WHERE id = %s", [body.stage, tid])
            audit.append(c, tid, p.subject, "tenant.stage",
                         {"from": t["stage"], "to": body.stage, "check_note": body.check_note})
            return clean(load_tenant(c, tid))

    @app.put("/tenants/{tid}/pilot-devices")
    def set_pilot(tid: str, body: PilotIn, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        ids = sorted(set(body.device_ids))
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            rows = c.execute("SELECT id, protected_flag FROM devices WHERE id = ANY(%s)", [ids]).fetchall()
            found = {r["id"]: r for r in rows}
            missing = [i for i in ids if i not in found]
            if missing:
                raise HTTPException(422, f"unknown devices (sync first): {missing}")
            if any(r["protected_flag"] for r in rows):
                raise HTTPException(409, "a protected device cannot be a pilot device")
            c.execute("DELETE FROM pilot_devices")
            for i in ids:
                c.execute("INSERT INTO pilot_devices (tenant_id, device_id) VALUES (%s, %s)", [tid, i])
            audit.append(c, tid, p.subject, "tenant.pilot_devices", {"device_ids": ids})
            return {"pilot_devices": ids}

    @app.post("/tenants/{tid}/protected-serials", status_code=201)
    def add_protected(tid: str, body: ProtectedIn, p: Principal = Depends(current_principal),
                      db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        serials = sorted({s.strip() for s in body.serials if s.strip()})
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            for s in serials:
                c.execute("INSERT INTO protected_serials (tenant_id, serial, note, created_by) VALUES (%s,%s,%s,%s) "
                          "ON CONFLICT DO NOTHING", [tid, s, body.note, p.subject])
            c.execute("UPDATE devices SET protected_flag = true WHERE serial = ANY(%s)", [serials])
            audit.append(c, tid, p.subject, "protected_serials.add", {"count": len(serials), "note": body.note})
            return {"added": len(serials)}

    @app.get("/tenants/{tid}/protected-serials")
    def list_protected(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            return [clean(r) for r in c.execute("SELECT serial, note, created_by, created_at FROM protected_serials "
                                                "ORDER BY serial")]

    # ------------------------------------------------------------ devices
    @app.post("/tenants/{tid}/devices/sync")
    def sync_devices(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db),
                     g: amapi.AmapiClient = Depends(get_amapi)):
        authorise(db, p, tid, "operator")
        with db.tenant(tid) as c:
            t = load_tenant(c, tid)
            if not t["enterprise"]:
                raise HTTPException(409, "tenant has no AMAPI enterprise bound yet")
            listed = [amapi.device_from_amapi(d) for d in g.list_devices(t["enterprise"])]
            protected = {r["serial"] for r in c.execute("SELECT serial FROM protected_serials")}
            newly_flagged = []
            for d in listed:
                flag = d["serial"] in protected
                prev = c.execute("SELECT protected_flag FROM devices WHERE id = %s", [d["id"]]).fetchone()
                if flag and not (prev and prev["protected_flag"]):
                    newly_flagged.append({"device_id": d["id"], "serial": d["serial"]})
                c.execute(
                    "INSERT INTO devices (tenant_id, id, amapi_name, serial, state, policy_name, applied_policy_name, "
                    " policy_compliant, last_status_at, enrolled_at, protected_flag, synced_at) "
                    "VALUES (%(t)s, %(id)s, %(amapi_name)s, %(serial)s, %(state)s, %(policy_name)s, "
                    " %(applied_policy_name)s, %(policy_compliant)s, %(last_status_at)s, %(enrolled_at)s, %(flag)s, now()) "
                    "ON CONFLICT (tenant_id, id) DO UPDATE SET amapi_name = EXCLUDED.amapi_name, "
                    " serial = EXCLUDED.serial, state = EXCLUDED.state, policy_name = EXCLUDED.policy_name, "
                    " applied_policy_name = EXCLUDED.applied_policy_name, policy_compliant = EXCLUDED.policy_compliant, "
                    " last_status_at = EXCLUDED.last_status_at, enrolled_at = EXCLUDED.enrolled_at, "
                    " protected_flag = devices.protected_flag OR EXCLUDED.protected_flag, synced_at = now()",
                    {**d, "t": tid, "flag": flag})
            ids = [d["id"] for d in listed]
            missing = c.execute("UPDATE devices SET state = 'NOT_LISTED', synced_at = now() "
                                "WHERE NOT (id = ANY(%s)) AND state IS DISTINCT FROM 'NOT_LISTED' RETURNING id",
                                [ids]).fetchall()
            for f in newly_flagged:
                audit.append(c, tid, "system", "alert.protected_device_enrolled", f)
            audit.append(c, tid, p.subject, "devices.sync",
                         {"listed": len(listed), "not_listed": len(missing), "protected_flagged": len(newly_flagged)})
            return {"listed": len(listed), "not_listed": len(missing), "protected_flagged": newly_flagged}

    @app.get("/tenants/{tid}/devices")
    def list_devices(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            return [clean(r) for r in c.execute("SELECT * FROM devices ORDER BY id")]

    @app.post("/tenants/{tid}/devices/{did}/commands", status_code=201)
    def command(tid: str, did: str, body: CommandIn, p: Principal = Depends(current_principal),
                db: Database = Depends(get_db), g: amapi.AmapiClient = Depends(get_amapi)):
        if not p.is_super:
            authorise(db, p, tid, "admin")   # records the attempt; admins still are not enough
            with db.tenant(tid) as c:
                audit.append(c, tid, p.subject, "access.denied", {"needed": "super_admin", "action": "command"})
            raise HTTPException(403, "device commands need a super-admin")
        detail = {"device_id": did, "type": body.type}
        if body.type not in amapi.ALLOWED_COMMANDS:
            with db.tenant(tid) as c:
                load_tenant(c, tid)
                audit.append(c, tid, p.subject, "device.command.refused", detail)
            raise HTTPException(422, f"command not allowed: only {sorted(amapi.ALLOWED_COMMANDS)}")
        try:
            with db.tenant(tid) as c:
                t = load_tenant(c, tid)
                require_active(t)
                d = c.execute("SELECT * FROM devices WHERE id = %s", [did]).fetchone()
                if not d:
                    raise HTTPException(404, "device not found")
                if d["protected_flag"]:
                    raise HTTPException(409, "device is on the protected list; no commands")
                if d["state"] != "ACTIVE":
                    raise HTTPException(409, f"device state is {d['state']}")
                row = c.execute("INSERT INTO commands (tenant_id, device_id, type, requested_by) "
                                "VALUES (%s, %s, %s, %s) RETURNING id, created_at",
                                [tid, did, body.type, p.subject]).fetchone()
                audit.append(c, tid, p.subject, "device.command", {**detail, "command_id": str(row["id"])})
                g.issue_command(d["amapi_name"], body.type)
                return {"id": str(row["id"]), "type": body.type, "device_id": did}
        except (HTTPException, amapi.NotConfigured):
            raise
        except Exception as e:
            record_failure(db, tid, p.subject, "device.command", detail, e)
            raise HTTPException(502, "Google call failed; the command was not recorded") from None

    # ------------------------------------------------------------ policies
    @app.post("/tenants/{tid}/policies/{name}/versions", status_code=201)
    def create_version(tid: str, name: str, body: PolicyVersionIn, p: Principal = Depends(current_principal),
                       db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        if not policy_name_ok(name):
            raise HTTPException(422, "policy name must be lowercase letters, digits and hyphens")
        if body.template is not None:
            if body.template not in policy.TEMPLATES:
                raise HTTPException(422, f"unknown template; known: {sorted(policy.TEMPLATES)}")
            content = json.loads(json.dumps(policy.TEMPLATES[body.template]))
        else:
            content = body.body or {}
        errors = policy.validate(content)
        if errors:
            raise HTTPException(422, errors)
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            c.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", [f"policy:{tid}:{name}"])
            last = c.execute("SELECT coalesce(max(version), 0) AS v FROM policy_versions WHERE name = %s",
                             [name]).fetchone()["v"]
            version = last + 1
            c.execute("INSERT INTO policy_versions (tenant_id, name, version, body, note, created_by) "
                      "VALUES (%s, %s, %s, %s, %s, %s)", [tid, name, version, Jsonb(content), body.note, p.subject])
            audit.append(c, tid, p.subject, "policy.version.create",
                         {"name": name, "version": version, "template": body.template,
                          "sha256": hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()})
            return {"name": name, "version": version, "body": content}

    @app.get("/tenants/{tid}/policies")
    def list_policies(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            return [clean(r) for r in c.execute(
                "SELECT name, max(version) AS latest, count(*) AS versions FROM policy_versions GROUP BY name "
                "ORDER BY name")]

    @app.get("/tenants/{tid}/policies/{name}/versions/{version}")
    def get_version(tid: str, name: str, version: int, p: Principal = Depends(current_principal),
                    db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            row = c.execute("SELECT * FROM policy_versions WHERE name = %s AND version = %s", [name, version]).fetchone()
            if not row:
                raise HTTPException(404, "policy version not found")
            return clean(row)

    @app.post("/tenants/{tid}/policies/{name}/versions/{version}/dry-run", status_code=201)
    def dry_run(tid: str, name: str, version: int, p: Principal = Depends(current_principal),
                db: Database = Depends(get_db)):
        authorise(db, p, tid, "operator")
        with db.tenant(tid) as c:
            t = load_tenant(c, tid)
            v = c.execute("SELECT body FROM policy_versions WHERE name = %s AND version = %s",
                          [name, version]).fetchone()
            if not v:
                raise HTTPException(404, "policy version not found")
            prev = c.execute("SELECT body FROM policy_versions WHERE name = %s AND version = %s",
                             [name, version - 1]).fetchone()
            change = policy.diff(prev["body"] if prev else None, v["body"])
            target = amapi.policy_name(t["enterprise"], policy.policy_id(name, version)) if t["enterprise"] else None
            pilot = {r["device_id"] for r in c.execute("SELECT device_id FROM pilot_devices")}
            devices = c.execute("SELECT id, serial, state, policy_name, protected_flag FROM devices ORDER BY id").fetchall()
            touch, protected, inactive, outside, already = [], 0, 0, 0, 0
            for d in devices:
                if d["protected_flag"]:
                    protected += 1
                elif d["state"] != "ACTIVE":
                    inactive += 1
                elif not rings.selected(tid, d["id"], t["stage"], pilot):
                    outside += 1
                elif d["policy_name"] == target:
                    already += 1
                else:
                    touch.append({"device_id": d["id"], "serial": d["serial"], "current_policy": d["policy_name"]})
            warnings = []
            if t["stage"] == "pilot" and not pilot:
                warnings.append("stage is pilot but no pilot devices are set")
            if t["paused"]:
                warnings.append("tenant is paused; apply will be refused until it is resumed")
            if not t["enterprise"]:
                warnings.append("tenant has no AMAPI enterprise bound yet")
            ids = [d["device_id"] for d in touch]
            row = c.execute("INSERT INTO dry_runs (tenant_id, policy_name, version, stage, device_ids, diff, created_by) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id, created_at",
                            [tid, name, version, t["stage"], Jsonb(ids), Jsonb(change), p.subject]).fetchone()
            audit.append(c, tid, p.subject, "policy.dry_run",
                         {"dry_run_id": str(row["id"]), "name": name, "version": version, "stage": t["stage"],
                          "would_touch": len(ids)})
            return {"dry_run_id": str(row["id"]), "stage": t["stage"], "policy": target, "diff": change,
                    "would_touch": touch,
                    "skipped": {"protected": protected, "inactive": inactive, "outside_ring": outside,
                                "already_on_policy": already},
                    "total_devices": len(devices), "warnings": warnings,
                    "expires_at": dt(row["created_at"] + timedelta(hours=config.dry_run_max_age_hours()))}

    @app.post("/tenants/{tid}/dry-runs/{run_id}/apply")
    def apply(tid: str, run_id: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db),
              g: amapi.AmapiClient = Depends(get_amapi)):
        authorise(db, p, tid, "admin")
        done: list[str] = []
        detail: dict[str, Any] = {"dry_run_id": run_id}
        try:
            with db.tenant(tid) as c:
                t = load_tenant(c, tid)
                require_active(t)
                try:
                    run = c.execute("SELECT * FROM dry_runs WHERE id = %s FOR UPDATE", [run_id]).fetchone()
                except psycopg.errors.InvalidTextRepresentation:
                    raise HTTPException(404, "dry run not found") from None
                if not run:
                    raise HTTPException(404, "dry run not found")
                if run["applied_at"]:
                    raise HTTPException(409, "dry run already applied")
                if now() - run["created_at"] > timedelta(hours=config.dry_run_max_age_hours()):
                    raise HTTPException(409, "dry run is too old; run it again")
                if run["stage"] != t["stage"]:
                    raise HTTPException(409, "rollout stage changed since the dry run; run it again")
                body = c.execute("SELECT body FROM policy_versions WHERE name = %s AND version = %s",
                                 [run["policy_name"], run["version"]]).fetchone()["body"]
                detail.update(name=run["policy_name"], version=run["version"], stage=run["stage"])
                pname = g.upsert_policy(t["enterprise"], policy.policy_id(run["policy_name"], run["version"]), body)
                skipped = []
                for did in run["device_ids"]:
                    d = c.execute("SELECT * FROM devices WHERE id = %s", [did]).fetchone()
                    # Re-check at apply time: a device may have been flagged or gone inactive since the dry run.
                    if not d or d["protected_flag"] or d["state"] != "ACTIVE":
                        skipped.append(did)
                        continue
                    g.set_device_policy(d["amapi_name"], pname)
                    done.append(did)
                    c.execute("UPDATE devices SET policy_name = %s WHERE id = %s", [pname, did])
                c.execute("UPDATE dry_runs SET applied_at = now(), applied_by = %s WHERE id = %s", [p.subject, run_id])
                audit.append(c, tid, p.subject, "policy.apply",
                             {**detail, "policy": pname, "devices": done, "skipped": skipped})
                return {"policy": pname, "applied_to": done, "skipped": skipped}
        except (HTTPException, amapi.NotConfigured):
            raise
        except Exception as e:
            # Google may have accepted some devices before the failure; record exactly which.
            record_failure(db, tid, p.subject, "policy.apply", {**detail, "devices_changed_at_google": done}, e)
            raise HTTPException(502, f"Google call failed after {len(done)} device(s); see audit log, then sync") from None

    # ------------------------------------------------------------ enrolment
    @app.post("/tenants/{tid}/enrolment-tokens", status_code=201)
    def create_token(tid: str, body: TokenIn, p: Principal = Depends(current_principal),
                     db: Database = Depends(get_db), g: amapi.AmapiClient = Depends(get_amapi)):
        authorise(db, p, tid, "admin")
        if not body.attest_new_or_factory_reset:
            raise HTTPException(422, "enrolment is only for new or factory-reset tablets; attest to continue")
        detail = {"policy_name": body.policy_name, "version": body.version, "ttl_hours": body.ttl_hours,
                  "one_time_only": body.one_time_only}
        try:
            with db.tenant(tid) as c:
                t = load_tenant(c, tid)
                require_active(t)
                v = c.execute("SELECT body FROM policy_versions WHERE name = %s AND version = %s",
                              [body.policy_name, body.version]).fetchone()
                if not v:
                    raise HTTPException(404, "policy version not found")
                pname = g.upsert_policy(t["enterprise"], policy.policy_id(body.policy_name, body.version), v["body"])
                tok = g.create_enrollment_token(t["enterprise"], pname, body.ttl_hours * 3600, body.one_time_only,
                                                f"tenant={tid}")
                expires = datetime.fromisoformat(tok["expirationTimestamp"].replace("Z", "+00:00"))
                row = c.execute(
                    "INSERT INTO enrolment_tokens (tenant_id, policy_name, version, amapi_name, token_sha256, "
                    " one_time_only, expires_at, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    [tid, body.policy_name, body.version, tok.get("name"),
                     hashlib.sha256(tok["value"].encode()).hexdigest(), body.one_time_only, expires, p.subject],
                ).fetchone()
                audit.append(c, tid, p.subject, "enrolment.token.create", {**detail, "token_id": str(row["id"])})
                # The token value is returned once and never stored.
                return {"id": str(row["id"]), "value": tok["value"], "qr_code": tok.get("qrCode"),
                        "policy": pname, "expires_at": dt(expires)}
        except (HTTPException, amapi.NotConfigured):
            raise
        except Exception as e:
            record_failure(db, tid, p.subject, "enrolment.token.create", detail, e)
            raise HTTPException(502, "Google call failed; no token was issued") from None

    # ------------------------------------------------------------ audit
    @app.get("/tenants/{tid}/audit")
    def audit_tail(tid: str, limit: int = 50, p: Principal = Depends(current_principal),
                   db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            return [clean(r) for r in audit.records(c, tid, limit=max(1, min(limit, 500)), newest_first=True)]

    @app.get("/tenants/{tid}/audit/verify")
    def audit_verify(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "viewer")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            rows = audit.records(c, tid)
        ok, bad = audit.verify_records(rows)
        return {"ok": ok, "first_bad_seq": bad, "records": len(rows), "head": rows[-1]["hash"] if rows else None}

    @app.get("/tenants/{tid}/audit/export", response_class=PlainTextResponse)
    def audit_export(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "admin")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            rows = audit.records(c, tid)
            audit.append(c, tid, p.subject, "audit.export", {"records": len(rows)})
        return PlainTextResponse("".join(audit.export_line(r) + "\n" for r in rows),
                                 media_type="application/x-ndjson",
                                 headers={"Content-Disposition": f'attachment; filename="{tid}-audit.jsonl"'})

    @app.get("/platform/audit/verify")
    def platform_verify(p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        require_super(db, p, "platform.audit.verify")
        with db.platform() as c:
            rows = audit.records(c, PLATFORM_CHAIN)
        ok, bad = audit.verify_records(rows)
        return {"ok": ok, "first_bad_seq": bad, "records": len(rows)}

    # ------------------------------------------------------------ read-only adapter for sl.p4sgi
    @app.get("/readonly/v1/tenants/{tid}/devices")
    def readonly_devices(tid: str, p: Principal = Depends(current_principal), db: Database = Depends(get_db)):
        authorise(db, p, tid, "reader")
        with db.tenant(tid) as c:
            load_tenant(c, tid)
            rows = c.execute("SELECT id, serial, state, policy_name, policy_compliant, last_status_at, "
                             "protected_flag, synced_at FROM devices ORDER BY id").fetchall()
        devices = [clean(r) for r in rows]
        return {
            "tenant": tid,
            "generated_at": dt(now()),
            "counts": {
                "total": len(rows),
                "active": sum(r["state"] == "ACTIVE" for r in rows),
                "compliant": sum(r["policy_compliant"] is True for r in rows),
                "non_compliant": sum(r["policy_compliant"] is False for r in rows),
                "protected_flagged": sum(r["protected_flag"] for r in rows),
            },
            "devices": devices,
        }

    return app


def policy_name_ok(name: str) -> bool:
    import re
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{1,40}", name))
