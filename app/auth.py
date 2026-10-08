"""Who is calling, and what they may do.

CRYPTSAT_AUTH selects the mode:
  none (default)  every request is refused with 401.
  oidc            single sign-on. Callers send "Authorization: Bearer <token>" from the configured identity
                  provider. The token is verified (app/oidc.py), the caller is identified by verified email
                  (people) or by subject (service identities), and roles come from the role_grants table.
                  People must have signed in with MFA (see config.oidc_mfa). Each new token is audited once in
                  the platform chain as auth.login or auth.refused.
  dev             dev/test only: the principal comes from X-Dev-User and X-Dev-Roles headers, e.g.
                  "X-Dev-Roles: sl-mbsse:admin, *:super_admin".

Roles per tenant: viewer < operator < admin. 'reader' is the read-only adapter role for sl.p4sgi and can only
call /readonly. 'super_admin' on '*' is the small named platform group.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from . import audit, config
from .db import PLATFORM_CHAIN
from .oidc import InvalidToken, Verifier

RANK = {"viewer": 1, "operator": 2, "admin": 3}
KNOWN_ROLES = set(RANK) | {"reader", "super_admin"}
MFA_AMR = {"mfa", "otp", "hwk", "swk", "fpt", "face", "iris", "sc"}   # RFC 8176 values that imply a second factor
_ROLE_ITEM = re.compile(r"^(\*|[a-z][a-z0-9-]{1,30}):([a-z_]+)$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: dict[str, frozenset[str]] = field(default_factory=dict)
    kind: str = "human"

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


def subject_of(claims: dict[str, Any]) -> str:
    """Verified email when the provider vouches for it, otherwise 'sub:<subject>'."""
    email = str(claims.get("email", "")).strip().lower()
    if email and claims.get("email_verified") is True and _EMAIL.match(email):
        return email
    return f"sub:{claims['sub']}".lower()


def mfa_ok(claims: dict[str, Any], mode: str) -> bool:
    if mode == "idp-enforced":
        return True
    if mode.startswith("acr:"):
        return claims.get("acr") == mode[4:]
    amr = claims.get("amr")
    return isinstance(amr, list) and bool(MFA_AMR & {str(a).lower() for a in amr})


def check_identity(subject: str, kind: str, claims: dict[str, Any]) -> str | None:
    """Return a refusal reason, or None if this identity may proceed."""
    if kind == "human":
        if subject.startswith("sub:"):
            return "people must sign in with a verified email"
        domains = config.oidc_allowed_domains()
        if domains and subject.rsplit("@", 1)[1] not in domains:
            return "email domain not allowed"
        hosted = config.oidc_hosted_domains()
        if hosted and str(claims.get("hd", "")).lower() not in hosted:
            return "account is not in an allowed Google Workspace organisation"
        if not mfa_ok(claims, config.oidc_mfa()):
            return "sign-in did not use multi-factor authentication"
    return None


def _record_session(db: Any, token: str, subject: str, outcome: str, detail: dict[str, Any],
                    exp: int) -> None:
    digest = hashlib.sha256(token.encode()).hexdigest()
    with db.auth() as c:
        new = c.execute(
            "INSERT INTO auth_sessions (token_sha256, subject, outcome, expires_at) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT DO NOTHING RETURNING token_sha256",
            [digest, subject, outcome, datetime.fromtimestamp(exp, timezone.utc)]).fetchone()
        if new:
            # Session rows only de-duplicate sign-in audit; expired ones can go (the audit record stays).
            c.execute("DELETE FROM auth_sessions WHERE expires_at < now() - interval '1 day'")
            action = "auth.login" if outcome == "ok" else "auth.refused"
            audit.append(c, PLATFORM_CHAIN, subject, action, {"outcome": outcome, **detail})


def oidc_principal(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    token = token.strip()
    verifier: Verifier = request.app.state.oidc
    try:
        claims = verifier.verify(token)
    except InvalidToken as e:
        raise HTTPException(401, f"invalid token: {e}", headers={"WWW-Authenticate": "Bearer"}) from None

    db = request.app.state.db
    subject = subject_of(claims)
    with db.auth() as c:
        rows = c.execute("SELECT kind, tenant_id, role FROM role_grants WHERE subject = %s", [subject]).fetchall()
    kinds = {r["kind"] for r in rows}
    kind = kinds.pop() if len(kinds) == 1 else ("human" if not kinds else "mixed")
    reason = None
    if not rows:
        reason = "no access granted"
    elif kind == "mixed":
        reason = "identity has both human and service grants"
    else:
        reason = check_identity(subject, kind, claims)
    detail = {"kind": kind, "amr": claims.get("amr"), "acr": claims.get("acr")}
    _record_session(db, token, subject, "ok" if reason is None else reason, detail, int(claims["exp"]))
    if reason:
        raise HTTPException(403, reason)

    roles: dict[str, set[str]] = {}
    for r in rows:
        roles.setdefault(r["tenant_id"], set()).add(r["role"])
    return Principal(subject=subject, kind=kind, roles={k: frozenset(v) for k, v in roles.items()})


def current_principal(request: Request) -> Principal:
    mode = config.auth_mode()
    if mode == "oidc":
        return oidc_principal(request)
    if mode == "dev" and config.env() in config.DEV_ENVS:
        user = request.headers.get("x-dev-user", "").strip()
        if not user:
            raise HTTPException(401, "missing X-Dev-User")
        try:
            roles = parse_roles(request.headers.get("x-dev-roles", ""))
        except ValueError as e:
            raise HTTPException(401, str(e)) from e
        return Principal(subject=user, roles=roles)
    raise HTTPException(401, "authentication is not configured")
