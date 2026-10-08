"""Tenants: one per ministry. A tenant maps to one AMAPI enterprise and can be paused (kill switch)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

TENANT_ID = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


@dataclass
class Tenant:
    id: str
    name: str
    country: str
    region: str = ""          # data-residency region, decided per ministry (open legal question)
    enterprise: str | None = None   # AMAPI enterprise resource name, e.g. enterprises/LC0...
    paused: bool = False
    pilot_devices: set[str] = field(default_factory=set)
    stage: str = "pilot"      # rollout stage: pilot -> r5 -> r25 -> r100


class TenantStore:
    def __init__(self) -> None:
        self._t: dict[str, Tenant] = {}

    def create(self, t: Tenant) -> Tenant:
        if not TENANT_ID.match(t.id):
            raise ValueError("tenant id must be lowercase letters, digits and hyphens")
        if t.id in self._t:
            raise KeyError("tenant exists")
        self._t[t.id] = t
        return t

    def get(self, tid: str) -> Tenant | None:
        return self._t.get(tid)

    def all(self) -> list[Tenant]:
        return list(self._t.values())
