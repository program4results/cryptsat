"""Android Management API adapter.

The real Google client is NOT implemented: it needs partner validation, quota and a service account.
Until then there are two implementations:
  - UnconfiguredAmapi (default): every call raises NotConfigured, which the API turns into 503. Fail closed.
  - FakeAmapi (CRYPTSAT_AMAPI=fake, dev/test only): in memory, records every call.

Checked against developers.google.com/android/management/reference on 2026-10-08:
  - Command types include LOCK and REBOOT, and also WIPE (wipe is an issueCommand type), so WIPE must be
    blocked here, in the API, and in the database. It is.
  - EnrollmentToken has duration (a "<n>s" string; default 1 hour), policyName, oneTimeOnly, qrCode,
    additionalData, value, expirationTimestamp.
NOT verified yet (confirm before the real client): the Device field names used in device_from_amapi(), the
allowed character set for policy ids, and whether policy assignment is a devices.patch of policyName.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

ALLOWED_COMMANDS = frozenset({"LOCK", "REBOOT"})   # WIPE is deliberately absent in phase 1


class NotConfigured(RuntimeError):
    pass


class AmapiClient(Protocol):
    def upsert_policy(self, enterprise: str, policy_id: str, body: dict[str, Any]) -> str: ...
    def list_devices(self, enterprise: str) -> list[dict[str, Any]]: ...
    def set_device_policy(self, device_name: str, policy_name: str) -> None: ...
    def create_enrollment_token(self, enterprise: str, policy_name: str, duration_seconds: int,
                                one_time_only: bool, additional_data: str) -> dict[str, Any]: ...
    def issue_command(self, device_name: str, command: str) -> None: ...


def check_command(command: str) -> None:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowed: {command}")


def policy_name(enterprise: str, policy_id: str) -> str:
    return f"{enterprise}/policies/{policy_id}"


class UnconfiguredAmapi:
    def _no(self, *_: Any, **__: Any) -> Any:
        raise NotConfigured("AMAPI is not configured. The real client waits for Google partner validation and quota.")

    upsert_policy = list_devices = set_device_policy = create_enrollment_token = issue_command = _no


class FakeAmapi:
    def __init__(self) -> None:
        self.devices: dict[str, dict[str, dict[str, Any]]] = {}    # enterprise -> device name -> Device
        self.policies: dict[str, dict[str, Any]] = {}             # policy name -> body
        self.tokens: list[dict[str, Any]] = []
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.fail_on: set[str] = set()                            # method names that should raise (tests)

    def _call(self, method: str, *args: Any) -> None:
        self.calls.append((method, args))
        if method in self.fail_on:
            raise RuntimeError(f"fake failure in {method}")

    def add_device(self, enterprise: str, device_id: str, serial: str, **extra: Any) -> dict[str, Any]:
        name = f"{enterprise}/devices/{device_id}"
        dev = {"name": name, "state": "ACTIVE", "hardwareInfo": {"serialNumber": serial},
               "enrollmentTime": "2026-10-01T08:00:00Z", "lastStatusReportTime": "2026-10-08T08:00:00Z",
               "policyCompliant": True, **extra}
        self.devices.setdefault(enterprise, {})[name] = dev
        return dev

    def upsert_policy(self, enterprise: str, policy_id: str, body: dict[str, Any]) -> str:
        self._call("upsert_policy", enterprise, policy_id)
        name = policy_name(enterprise, policy_id)
        self.policies[name] = body
        return name

    def list_devices(self, enterprise: str) -> list[dict[str, Any]]:
        self._call("list_devices", enterprise)
        return [dict(d) for d in self.devices.get(enterprise, {}).values()]

    def set_device_policy(self, device_name: str, policy_name: str) -> None:
        self._call("set_device_policy", device_name, policy_name)
        enterprise = device_name.split("/devices/")[0]
        self.devices[enterprise][device_name]["policyName"] = policy_name

    def create_enrollment_token(self, enterprise: str, policy_name: str, duration_seconds: int,
                                one_time_only: bool, additional_data: str) -> dict[str, Any]:
        self._call("create_enrollment_token", enterprise, policy_name)
        if policy_name not in self.policies:
            raise RuntimeError("policy does not exist")
        tid = secrets.token_hex(8)
        value = secrets.token_urlsafe(24)
        expires = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        tok = {"name": f"{enterprise}/enrollmentTokens/{tid}", "value": value, "policyName": policy_name,
               "duration": f"{duration_seconds}s", "oneTimeOnly": one_time_only, "additionalData": additional_data,
               "expirationTimestamp": expires.isoformat().replace("+00:00", "Z"),
               "qrCode": '{"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE":{"com.google.android.apps.work.'
                         'clouddpc.EXTRA_ENROLLMENT_TOKEN":"' + value + '"}}'}
        self.tokens.append(tok)
        return tok

    def issue_command(self, device_name: str, command: str) -> None:
        check_command(command)
        self._call("issue_command", device_name, command)


def device_from_amapi(d: dict[str, Any]) -> dict[str, Any]:
    """Map an AMAPI Device to our columns. Field names NOT verified against Google's Device reference yet."""
    name = d["name"]
    return {
        "id": name.rsplit("/", 1)[-1],
        "amapi_name": name,
        "serial": (d.get("hardwareInfo") or {}).get("serialNumber"),
        "state": d.get("state"),
        "policy_name": d.get("policyName"),
        "applied_policy_name": d.get("appliedPolicyName"),
        "policy_compliant": d.get("policyCompliant"),
        "last_status_at": d.get("lastStatusReportTime"),
        "enrolled_at": d.get("enrollmentTime"),
    }


def make_client(mode: str) -> AmapiClient:
    if mode == "fake":
        return FakeAmapi()
    return UnconfiguredAmapi()
