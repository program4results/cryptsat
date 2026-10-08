"""Who is calling, and what they may do.

Production authentication is SSO with MFA through OIDC, which is NOT wired yet, so in the default mode
every request is refused (401). For development and tests only, CRYPTSAT_AUTH=dev reads the principal from
two headers:

    X-Dev-User:  alice@example.org
    X-Dev-Roles: sl-mbsse:admin, gm-mobse:viewer, *:super_admin

Roles per tenant: viewer < operator < admin. 'reader' is the read-only adapter role for sl.p4sgi and can only
call /readonly. 'super_admin' on '*' is the small named platform group (tenants, enterprise binding, commands).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

from . import config

RANK = {"viewer": 1, "operator": 2, "admin": 3}
KNOWN_ROLES = set(RANK) | {"reader", "super_admin"}
_ROLE_ITEM = re.compile(r"^(\*|[a-z][a-z0-9-]{1,30}):([a-z_]+)$")


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def is_super(self) -> bool:
        return "super_admin" in self.roles.get("*", frozenset())

    def level(self, tenant_id: str) -> int:
        return max((RANK.get(r, 0) for r in self.roles.get(tenant_id, ())), default=0)

    def can(self, tenant_id: str, role: str) -> bool:
        if self.is_super:
            return True
        if role == "reader":
            return "reader" in self.roles.get(tenant_id, ()) or self.level(tenant_id) >= RANK["viewer"]
        return self.level(tenant_id) >= RANK[role]

    def tenant_ids(self) -> list[str]:
        return sorted(t for t in self.roles if t != "*")


def parse_roles(raw: str) -> dict[str, frozenset[str]]:
    out: dict[str, set[str]] = {}
    for item in (s.strip() for s in raw.split(",")):
        if not item:
            continue
        m = _ROLE_ITEM.match(item)
        if not m or m.group(2) not in KNOWN_ROLES:
            raise ValueError(f"bad role entry: {item!r}")
        tenant, role = m.groups()
        if (tenant == "*") != (role == "super_admin"):
            raise ValueError("super_admin is only valid on '*', and '*' only takes super_admin")
        out.setdefault(tenant, set()).add(role)
    return {k: frozenset(v) for k, v in out.items()}


def current_principal(request: Request) -> Principal:
    mode = config.auth_mode()
    if mode == "dev" and config.env() in config.DEV_ENVS:
        user = request.headers.get("x-dev-user", "").strip()
        if not user:
            raise HTTPException(401, "missing X-Dev-User")
        try:
            roles = parse_roles(request.headers.get("x-dev-roles", ""))
        except ValueError as e:
            raise HTTPException(401, str(e)) from e
        return Principal(subject=user, roles=roles)
    raise HTTPException(401, "authentication is not configured (OIDC with MFA is pending)")
