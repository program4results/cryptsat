"""Android Management API adapter. The real client is NOT implemented: it needs a Google quota and credentials.
Until then only the in-memory fake exists (tests, dev), and everything else fails closed."""
from __future__ import annotations

import secrets
from typing import Any

from . import config

ALLOWED_COMMANDS = {"LOCK", "REBOOT"}   # WIPE is deliberately absent in phase 1


class NotConfigured(RuntimeError):
    pass


class FakeAmapi:
    def __init__(self) -> None:
        self.devices: dict[str, dict[str, dict[str, Any]]] = {}   # enterprise -> device id -> info
        self.policies: dict[str, dict[str, dict[str, Any]]] = {}
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def list_devices(self, enterprise: str) -> list[dict[str, Any]]:
        return list(self.devices.get(enterprise, {}).values())

    def get_policy(self, enterprise: str, name: str) -> dict[str, Any] | None:
        return self.policies.get(enterprise, {}).get(name)

    def apply_policy(self, enterprise: str, name: str, policy: dict[str, Any]) -> None:
        self.calls.append(("apply_policy", (enterprise, name)))
        self.policies.setdefault(enterprise, {})[name] = policy

    def create_enrolment_token(self, enterprise: str, policy_name: str, ttl_seconds: int) -> dict[str, Any]:
        self.calls.append(("token", (enterprise, policy_name)))
        return {"value": secrets.token_urlsafe(16), "policy": policy_name, "ttl_seconds": ttl_seconds}

    def issue_command(self, enterprise: str, device_id: str, command: str) -> None:
        if command not in ALLOWED_COMMANDS:
            raise ValueError("command not allowed")
        self.calls.append(("command", (enterprise, device_id, command)))


_client: FakeAmapi | None = None


def get_client() -> FakeAmapi:
    global _client
    mode = config.amapi_mode()
    if mode == "fake":
        if _client is None:
            _client = FakeAmapi()
        return _client
    raise NotConfigured("AMAPI is not configured (CRYPTSAT_AMAPI=none). Real client waits for Google quota and credentials.")


def reset_client() -> None:
    global _client
    _client = None
