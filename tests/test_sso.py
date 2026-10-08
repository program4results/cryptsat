"""Single sign-on: token verification, grants, MFA, service identities and sign-in audit."""
from __future__ import annotations

import time
import uuid

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from app import grants
from app.main import create_app
from app.oidc import InvalidToken, Verifier
from tests.conftest import OWNER_DSN

ISS = "https://login.example.org"
AUD = "cryptsat-client-id"


class IdP:
    """A minimal identity provider: signing keys, a JWKS and token minting."""

    def __init__(self) -> None:
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.kids = {"r1": (self.rsa, "RS256"), "e1": (self.ec, "ES256")}
        self.fetches: list[str] = []

    def jwks(self) -> dict:
        keys = []
        for kid, (k, alg) in self.kids.items():
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key(), as_dict=True) if alg == "RS256" \
                else jwt.algorithms.ECAlgorithm.to_jwk(k.public_key(), as_dict=True)
            keys.append({**jwk, "kid": kid, "alg": alg, "use": "sig"})
        return {"keys": keys}

    def fetch(self, url: str) -> dict:
        self.fetches.append(url)
        if url == f"{ISS}/.well-known/openid-configuration":
            return {"issuer": ISS, "jwks_uri": f"{ISS}/jwks"}
        if url == f"{ISS}/jwks":
            return self.jwks()
        raise AssertionError(url)

    def token(self, kid: str = "r1", **claims) -> str:
        now = int(time.time())
        body = {"iss": ISS, "aud": AUD, "sub": "u-" + uuid.uuid4().hex[:8], "iat": now, "exp": now + 3600,
                "jti": uuid.uuid4().hex, **claims}
        body = {k: v for k, v in body.items() if v is not None}
        key, alg = self.kids[kid]
        return jwt.encode(body, key, algorithm=alg, headers={"kid": kid})

    def person(self, email: str, mfa: bool = True, **claims) -> str:
        amr = ["pwd", "mfa"] if mfa else ["pwd"]
        return self.token(email=email, email_verified=True, amr=amr, **claims)


def bearer(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def idp() -> IdP:
    return IdP()


@pytest.fixture
def sso(database, fake, idp, monkeypatch) -> TestClient:
    monkeypatch.setenv("CRYPTSAT_AUTH", "oidc")
    monkeypatch.setenv("CRYPTSAT_OIDC_ISSUER", ISS)
    monkeypatch.setenv("CRYPTSAT_OIDC_AUDIENCE", AUD)
    monkeypatch.delenv("CRYPTSAT_OIDC_MFA", raising=False)
    monkeypatch.delenv("CRYPTSAT_OIDC_ALLOWED_DOMAINS", raising=False)
    # Clear grants so each test starts with no super-admin. Even the owner needs platform scope (forced RLS).
    with psycopg.connect(OWNER_DSN, autocommit=True) as c, c.transaction():
        c.execute("SELECT set_config('app.scope', 'platform', true)")
        c.execute("DELETE FROM role_grants")
    return TestClient(create_app(db=database, amapi_client=fake, oidc_verifier=Verifier(ISS, AUD, fetch=idp.fetch)))


@pytest.fixture
def root(sso, database, idp) -> dict[str, str]:
    grants.bootstrap(database, "root@saltracker.example")
    return bearer(idp.person("root@saltracker.example"))


def platform_actions(sso, root) -> list[str]:
    from app import audit
    db = sso.app.state.db
    with db.platform() as c:
        return [r["action"] for r in audit.records(c, "_platform")]


# ---------------------------------------------------------------- the verifier on its own
def test_verifier_accepts_good_tokens_and_rejects_bad_ones(idp):
    v = Verifier(ISS, AUD, fetch=idp.fetch)
    assert v.verify(idp.token())["iss"] == ISS
    assert v.verify(idp.token(kid="e1"))["aud"] == AUD
    now = int(time.time())
    bad = {
        "wrong audience": idp.token(aud="someone-else"),
        "wrong issuer": idp.token(iss="https://evil.example"),
        "expired": idp.token(iat=now - 7200, exp=now - 3600),
        "issued in the future": idp.token(iat=now + 3600, exp=now + 7200),
        "no subject": idp.token(sub=None),
        "no expiry": idp.token(exp=None),
        "several audiences, no azp": idp.token(aud=[AUD, "other"]),
        "unsigned": jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "iat": now, "exp": now + 60}, None,
                               algorithm="none"),
        "shared-secret": jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "iat": now, "exp": now + 60},
                                    "secret-at-least-32-bytes-long-xxxxxx", algorithm="HS256", headers={"kid": "r1"}),
        "garbage": "not.a.token",
    }
    for why, tok in bad.items():
        with pytest.raises(InvalidToken):
            v.verify(tok)
            pytest.fail(why)
    assert v.verify(idp.token(aud=[AUD, "other"], azp=AUD))


def test_key_confusion_is_rejected(idp):
    # An ES256 token presented under the RSA key id must not verify.
    v = Verifier(ISS, AUD, fetch=idp.fetch)
    now = int(time.time())
    tok = jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "iat": now, "exp": now + 60}, idp.ec, algorithm="ES256",
                     headers={"kid": "r1"})
    with pytest.raises(InvalidToken):
        v.verify(tok)


def test_key_rotation_refetches_but_not_on_every_request(idp):
    clock = [1000.0]
    v = Verifier(ISS, AUD, fetch=idp.fetch, clock=lambda: clock[0])
    v.verify(idp.token())
    first = len(idp.fetches)            # discovery + jwks
    idp.kids["r2"] = (rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256")
    with pytest.raises(InvalidToken):   # within a minute of the last fetch: no refetch
        v.verify(idp.token(kid="r2"))
    assert len(idp.fetches) == first
    clock[0] += 61
    assert v.verify(idp.token(kid="r2"))
    assert len(idp.fetches) == first + 1


def test_discovery_must_name_the_same_issuer(idp):
    def fetch(url):
        return {"issuer": "https://evil.example", "jwks_uri": f"{ISS}/jwks"} if "well-known" in url else idp.jwks()
    with pytest.raises(InvalidToken):
        Verifier(ISS, AUD, fetch=fetch).verify(idp.token())


# ---------------------------------------------------------------- the API under SSO
def test_no_or_bad_token_is_401(sso, idp):
    assert sso.get("/me").status_code == 401
    assert sso.get("/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert sso.get("/me", headers=bearer(idp.token(aud="x"))).status_code == 401
    # Dev headers mean nothing in SSO mode.
    assert sso.get("/me", headers={"X-Dev-User": "a", "X-Dev-Roles": "*:super_admin"}).status_code == 401


def test_valid_sign_in_without_a_grant_is_refused_and_audited_once(sso, root, idp):
    tok = bearer(idp.person("stranger@example.org"))
    assert sso.get("/me", headers=tok).status_code == 403
    assert sso.get("/me", headers=tok).status_code == 403
    assert platform_actions(sso, root).count("auth.refused") == 1


def test_super_admin_bootstrap_and_login_audit(sso, root, database):
    me = sso.get("/me", headers=root).json()
    assert me == {**me, "subject": "root@saltracker.example", "super_admin": True, "kind": "human"}
    sso.get("/tenants", headers=root)
    actions = platform_actions(sso, root)
    assert actions.count("auth.login") == 1 and "grant.add" in actions
    with pytest.raises(grants.GrantError):
        grants.bootstrap(database, "second@saltracker.example")


@pytest.mark.parametrize("mode,claims,ok", [
    ("amr", {"amr": ["pwd"]}, False),
    ("amr", {"amr": ["pwd", "otp"]}, True),
    ("amr", {"amr": None}, False),
    ("acr:urn:mfa", {"amr": None, "acr": "urn:mfa"}, True),
    ("acr:urn:mfa", {"amr": ["mfa"], "acr": "urn:pwd"}, False),
    ("idp-enforced", {"amr": None}, True),
])
def test_people_need_mfa(sso, root, idp, monkeypatch, mode, claims, ok):
    r = sso.post("/grants", headers=root, json={"subject": "Ada@Ministry.example", "tenant_id": "*",
                                                "role": "super_admin"})
    assert r.status_code == 201 and r.json()["subject"] == "ada@ministry.example"
    monkeypatch.setenv("CRYPTSAT_OIDC_MFA", mode)
    tok = idp.token(email="ada@ministry.example", email_verified=True, **claims)
    assert (sso.get("/me", headers=bearer(tok)).status_code == 200) is ok


def test_unverified_email_is_not_trusted(sso, root, idp):
    sso.post("/grants", headers=root, json={"subject": "eve@ministry.example", "tenant_id": "*", "role": "super_admin"})
    tok = idp.token(email="eve@ministry.example", email_verified=False, amr=["mfa"])
    assert sso.get("/me", headers=bearer(tok)).status_code == 403


def test_allowed_domains(sso, root, idp, monkeypatch):
    monkeypatch.setenv("CRYPTSAT_OIDC_ALLOWED_DOMAINS", "saltracker.example, mbsse.gov.sl")
    assert sso.get("/me", headers=root).status_code == 200
    sso.post("/grants", headers=root, json={"subject": "x@gmail.com", "tenant_id": "*", "role": "super_admin"})
    assert sso.get("/me", headers=bearer(idp.person("x@gmail.com"))).status_code == 403


def test_tenant_roles_come_from_grants(sso, root, idp, fake):
    tid = f"t-{uuid.uuid4().hex[:6]}"
    assert sso.post("/tenants", headers=root, json={"id": tid, "name": "MBSSE", "country": "SL"}).status_code == 201
    ada = bearer(idp.person("ada@mbsse.example"))
    assert sso.get(f"/tenants/{tid}", headers=ada).status_code == 403
    r = sso.post("/grants", headers=root, json={"subject": "ada@mbsse.example", "tenant_id": tid, "role": "admin"})
    assert r.status_code == 201 and r.json()["created"]
    assert sso.get(f"/tenants/{tid}", headers=ada).status_code == 200
    assert sso.post(f"/tenants/{tid}/pause", headers=ada, json={"reason": "drill"}).status_code == 200
    # A tenant admin cannot grant, and sees only their own tenant's grants.
    assert sso.post("/grants", headers=ada, json={"subject": "bob@x.example", "tenant_id": tid,
                                                  "role": "admin"}).status_code == 403
    assert [g["subject"] for g in sso.get(f"/tenants/{tid}/grants", headers=ada).json()] == ["ada@mbsse.example"]
    tenant_log = [a["action"] for a in sso.get(f"/tenants/{tid}/audit", headers=ada).json()]
    assert "grant.add" in tenant_log
    # Revocation takes effect on the next request, even with the same token.
    r = sso.post("/grants/revoke", headers=root, json={"subject": "ada@mbsse.example", "tenant_id": tid,
                                                       "role": "admin"})
    assert r.status_code == 200
    assert sso.get(f"/tenants/{tid}", headers=ada).status_code == 403


def test_grant_rules(sso, root):
    def add(**b):
        return sso.post("/grants", headers=root, json={"kind": "human", **b}).status_code
    assert add(subject="a@x.example", tenant_id="no-such-tenant", role="admin") == 422
    assert add(subject="a@x.example", tenant_id="*", role="admin") == 422
    assert add(subject="sub:svc-1", kind="service", tenant_id="*", role="super_admin") == 422
    assert add(subject="sub:svc-1", tenant_id="*", role="super_admin") == 422          # people need an email
    assert add(subject="not-an-email", tenant_id="*", role="super_admin") == 422
    # Lock-out guard.
    r = sso.post("/grants/revoke", headers=root, json={"subject": "root@saltracker.example", "tenant_id": "*",
                                                       "role": "super_admin"})
    assert r.status_code == 409


def test_service_identity_can_only_read(sso, root, idp, fake):
    tid = f"t-{uuid.uuid4().hex[:6]}"
    sso.post("/tenants", headers=root, json={"id": tid, "name": "MBSSE", "country": "SL"})
    r = sso.post("/grants", headers=root, json={"subject": "sub:p4sgi-adapter", "kind": "service",
                                                "tenant_id": tid, "role": "reader"})
    assert r.status_code == 201
    assert sso.post("/grants", headers=root, json={"subject": "sub:p4sgi-adapter", "kind": "service",
                                                   "tenant_id": tid, "role": "admin"}).status_code == 422
    # The same identity cannot also hold a human grant.
    assert sso.post("/grants", headers=root, json={"subject": "sub:p4sgi-adapter", "kind": "human",
                                                   "tenant_id": tid, "role": "viewer"}).status_code == 422
    svc = bearer(idp.token(sub="p4sgi-adapter"))           # machine token: no email, no MFA claim
    assert sso.get(f"/readonly/v1/tenants/{tid}/devices", headers=svc).status_code == 200
    assert sso.get(f"/tenants/{tid}/devices", headers=svc).status_code == 403
    assert sso.post(f"/tenants/{tid}/pause", headers=svc, json={"reason": "nope"}).status_code == 403
    assert sso.get("/me", headers=svc).json()["kind"] == "service"


def test_oidc_mode_requires_issuer_and_audience(monkeypatch):
    from app import config
    monkeypatch.setenv("CRYPTSAT_AUTH", "oidc")
    monkeypatch.setenv("CRYPTSAT_OIDC_ISSUER", "http://insecure.example")
    monkeypatch.setenv("CRYPTSAT_OIDC_AUDIENCE", AUD)
    with pytest.raises(RuntimeError):
        config.check()
    monkeypatch.setenv("CRYPTSAT_OIDC_ISSUER", ISS)
    monkeypatch.setenv("CRYPTSAT_OIDC_MFA", "whatever")
    with pytest.raises(RuntimeError):
        config.check()
    monkeypatch.setenv("CRYPTSAT_OIDC_MFA", "amr")
    config.check()


def test_google_issuer_in_both_documented_forms():
    google = IdP()
    gi = "https://accounts.google.com"

    def fetch(url):
        return {"issuer": gi, "jwks_uri": f"{gi}/jwks"} if "well-known" in url else google.jwks()
    v = Verifier(gi, AUD, fetch=fetch)
    assert v.verify(google.token(iss="https://accounts.google.com"))
    assert v.verify(google.token(iss="accounts.google.com"))
    with pytest.raises(InvalidToken):
        v.verify(google.token(iss="accounts.google.com.evil.example"))
    # Other issuers get no aliases.
    with pytest.raises(InvalidToken):
        Verifier(ISS, AUD, fetch=google.fetch).verify(google.token(iss=ISS.removeprefix("https://")))


def test_hosted_domain_claim(sso, root, idp, monkeypatch):
    sso.post("/grants", headers=root, json={"subject": "ada@program4results.example", "tenant_id": "*",
                                            "role": "super_admin"})
    monkeypatch.setenv("CRYPTSAT_OIDC_HOSTED_DOMAINS", "saltracker.example,program4results.example")
    assert sso.get("/me", headers=bearer(idp.person("ada@program4results.example",
                                                    hd="program4results.example"))).status_code == 200
    assert sso.get("/me", headers=bearer(idp.person("ada@program4results.example",
                                                    hd="saltracker.example"))).status_code == 200
    # Same email but no organisation (a consumer account) or a different one: refused.
    assert sso.get("/me", headers=bearer(idp.person("ada@program4results.example"))).status_code == 403
    assert sso.get("/me", headers=bearer(idp.person("ada@program4results.example",
                                                    hd="other.example"))).status_code == 403
