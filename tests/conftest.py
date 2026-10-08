"""Tests run against a real Postgres, connecting as the non-owner service role so row-level security applies.

Local setup (once):  psql as a superuser -f db/bootstrap.sql, set passwords, CREATE DATABASE cryptsat_test
OWNER cryptsat_owner. Override the DSNs with CRYPTSAT_TEST_OWNER_DSN and CRYPTSAT_TEST_DSN.
The test database's public schema is dropped and rebuilt at the start of every run.
"""
from __future__ import annotations

import os
import secrets
from collections.abc import Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.amapi import FakeAmapi
from app.db import Database
from app.main import create_app
from app.migrate import migrate

OWNER_DSN = os.getenv("CRYPTSAT_TEST_OWNER_DSN", "postgresql://cryptsat_owner:owner@localhost/cryptsat_test")
APP_DSN = os.getenv("CRYPTSAT_TEST_DSN", "postgresql://cryptsat_app:app@localhost/cryptsat_test")

SUPER = {"X-Dev-User": "root@saltracker.example", "X-Dev-Roles": "*:super_admin"}


def who(user: str, roles: str) -> dict[str, str]:
    return {"X-Dev-User": user, "X-Dev-Roles": roles}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRYPTSAT_ENV", "test")
    monkeypatch.setenv("CRYPTSAT_AUTH", "dev")
    monkeypatch.setenv("CRYPTSAT_AMAPI", "fake")


@pytest.fixture(scope="session")
def database() -> Iterator[Database]:
    with psycopg.connect(OWNER_DSN, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS public CASCADE")
        c.execute("CREATE SCHEMA public")
    migrate(OWNER_DSN)
    db = Database(APP_DSN, max_size=4)
    db.open()
    yield db
    db.close()


@pytest.fixture
def fake() -> FakeAmapi:
    return FakeAmapi()


@pytest.fixture
def client(database: Database, fake: FakeAmapi, _env: None) -> TestClient:
    return TestClient(create_app(db=database, amapi_client=fake))


def new_tenant(client: TestClient, enterprise: bool = True) -> tuple[str, str | None]:
    tid = f"t-{secrets.token_hex(4)}"
    r = client.post("/tenants", headers=SUPER, json={"id": tid, "name": "Test ministry", "country": "SL"})
    assert r.status_code == 201, r.text
    ent = None
    if enterprise:
        ent = f"enterprises/LC{secrets.token_hex(5)}"
        r = client.post(f"/tenants/{tid}/enterprise", headers=SUPER, json={"enterprise": ent})
        assert r.status_code == 200, r.text
    return tid, ent


@pytest.fixture
def tenant(client: TestClient) -> tuple[str, str]:
    tid, ent = new_tenant(client)
    assert ent
    return tid, ent


def admin(tid: str) -> dict[str, str]:
    return who(f"admin@{tid}", f"{tid}:admin")


def operator(tid: str) -> dict[str, str]:
    return who(f"op@{tid}", f"{tid}:operator")


def viewer(tid: str) -> dict[str, str]:
    return who(f"view@{tid}", f"{tid}:viewer")


def enrol(client: TestClient, fake: FakeAmapi, tid: str, ent: str, n: int, prefix: str = "d") -> list[str]:
    ids = [f"{prefix}{i:03d}" for i in range(n)]
    for i in ids:
        fake.add_device(ent, i, serial=f"SN-{tid}-{i}")
    r = client.post(f"/tenants/{tid}/devices/sync", headers=operator(tid))
    assert r.status_code == 200, r.text
    return ids
