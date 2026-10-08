"""OpenID Connect token verification. The service is a resource server: callers present a bearer token issued
by the configured identity provider, and this module checks it. Signing keys come from the provider's JWKS.

Checks: signature (RS256 or ES256 only), issuer, audience (and azp when there are several audiences), expiry,
not-before, issued-at not in the future, and the subject claim. Keys are cached for an hour and re-fetched at
most once a minute when an unknown key id appears (key rotation).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from collections.abc import Callable
from typing import Any

import jwt

ALGORITHMS = ("RS256", "ES256")
LEEWAY_SECONDS = 60
KEY_TTL_SECONDS = 3600
REFETCH_MIN_SECONDS = 60

Fetch = Callable[[str], dict[str, Any]]

# Google documents that its ID tokens carry iss as either form (developers.google.com/identity/openid-connect,
# checked 2026-10-08). Other providers use exactly the configured issuer.
ISSUER_ALIASES = {"https://accounts.google.com": ("https://accounts.google.com", "accounts.google.com")}


class InvalidToken(Exception):
    pass


def https_fetch(url: str) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise InvalidToken("identity provider URLs must be https")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:   # noqa: S310 (scheme checked above)
        return json.loads(resp.read(1_000_000))


class Verifier:
    def __init__(self, issuer: str, audience: str, jwks_uri: str | None = None, fetch: Fetch = https_fetch,
                 clock: Callable[[], float] = time.time) -> None:
        if not issuer or not audience:
            raise ValueError("issuer and audience are required")
        self.issuer = issuer.rstrip("/")
        self.accepted_issuers = list(ISSUER_ALIASES.get(self.issuer, (self.issuer,)))
        self.audience = audience
        self._jwks_uri = jwks_uri
        self._fetch = fetch
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _jwks_url(self) -> str:
        if not self._jwks_uri:
            meta = self._fetch(f"{self.issuer}/.well-known/openid-configuration")
            if meta.get("issuer", "").rstrip("/") != self.issuer:
                raise InvalidToken("discovery document is for a different issuer")
            self._jwks_uri = meta["jwks_uri"]
        return self._jwks_uri

    def _refresh(self) -> None:
        jwks = self._fetch(self._jwks_url())
        keys = {}
        for k in jwks.get("keys", []):
            if k.get("use", "sig") != "sig" or "kid" not in k:
                continue
            try:
                keys[k["kid"]] = jwt.PyJWK(k)
            except jwt.PyJWTError:
                continue    # skip key types we do not accept
        self._keys = keys
        self._fetched_at = self._clock()

    def _key(self, kid: str) -> Any:
        with self._lock:
            age = self._clock() - self._fetched_at
            if age > KEY_TTL_SECONDS or (kid not in self._keys and age > REFETCH_MIN_SECONDS):
                try:
                    self._refresh()
                except InvalidToken:
                    raise
                except Exception as e:
                    if not self._keys:
                        raise InvalidToken("identity provider keys unavailable") from e
            if kid not in self._keys:
                raise InvalidToken("unknown signing key")
            return self._keys[kid]

    def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise InvalidToken("malformed token") from e
        alg = header.get("alg")
        if alg not in ALGORITHMS:
            raise InvalidToken("signing algorithm not accepted")
        key = self._key(str(header.get("kid", "")))
        if key.algorithm_name != alg:
            raise InvalidToken("algorithm does not match key")
        try:
            claims = jwt.decode(
                token, key.key, algorithms=[alg], audience=self.audience, issuer=self.accepted_issuers,
                leeway=LEEWAY_SECONDS, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise InvalidToken(type(e).__name__) from e
        aud = claims["aud"]
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.audience:
            raise InvalidToken("token has several audiences and azp is not this service")
        return claims
