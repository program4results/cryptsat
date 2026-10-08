"""Policy templates and validation. Only top-level keys in ALLOWED may be sent to Google.

Checked on 2026-10-08:
  - REST Policy reference: every key in ALLOWED exists on the Policy resource.
  - Google's generated library docs (developers.google.com/resources/api-libraries, undated revision):
      passwordRequirements is deprecated; use passwordPolicies.
      installUnknownSourcesAllowed is deprecated; replaced by advancedSecurityOverrides.untrustedAppsPolicy,
        whose default is already the most secure setting (no unknown sources), so the baseline omits it.
      statusReportingSettings subfields are as in STATUS_REPORTING_KEYS.
  - The current REST/MCP reference says safeBootDisabled is deprecated in favour of
    advancedSecurityOverrides.developerSettings.
NOT verified yet: whether debuggingFeaturesAllowed is also deprecated in favour of
advancedSecurityOverrides.developerSettings (likely; its enum values are unverified). The baseline still uses
debuggingFeaturesAllowed for the documented ADB exception; confirm before the first real enrolment.
"""
from __future__ import annotations

import json
from typing import Any

ALLOWED = frozenset({
    "applications", "debuggingFeaturesAllowed", "factoryResetDisabled", "passwordPolicies",
    "statusReportingSettings", "keyguardDisabled", "advancedSecurityOverrides",
})
DEPRECATED = {
    "passwordRequirements": "use passwordPolicies",
    "installUnknownSourcesAllowed": "use advancedSecurityOverrides.untrustedAppsPolicy (default is already secure)",
}
STATUS_REPORTING_KEYS = frozenset({
    "applicationReportingSettings", "applicationReportsEnabled", "deviceSettingsEnabled", "displayInfoEnabled",
    "hardwareStatusEnabled", "memoryInfoEnabled", "networkInfoEnabled", "powerManagementEventsEnabled",
    "softwareInfoEnabled", "systemPropertiesEnabled",
})
# Phase 1 never sets these: they can lock operators out or remove the device from management.
FORBIDDEN_VALUES: dict[str, Any] = {"keyguardDisabled": True}
MAX_BYTES = 256 * 1024

TEMPLATES: dict[str, dict[str, Any]] = {
    # Minimal baseline. ADB stays allowed so RUSTAiDMIN diagnostics still work (documented exception).
    # Status reporting stays minimal (data minimisation): enough to see compliance and device health.
    "baseline": {
        "debuggingFeaturesAllowed": True,
        "statusReportingSettings": {
            "applicationReportsEnabled": True,
            "deviceSettingsEnabled": True,
            "softwareInfoEnabled": True,
            "hardwareStatusEnabled": True,
        },
    },
}


def validate(policy: dict[str, Any]) -> list[str]:
    if not isinstance(policy, dict) or not policy:
        return ["policy must be a non-empty object"]
    errs = []
    for k in sorted(policy):
        if k in DEPRECATED:
            errs.append(f"deprecated policy key: {k} ({DEPRECATED[k]})")
        elif k not in ALLOWED:
            errs.append(f"unknown policy key: {k}")
    errs += [f"forbidden setting: {k}={v!r}" for k, v in sorted(policy.items())
             if k in FORBIDDEN_VALUES and v == FORBIDDEN_VALUES[k]]
    srs = policy.get("statusReportingSettings")
    if srs is not None:
        if not isinstance(srs, dict):
            errs.append("statusReportingSettings must be an object")
        else:
            errs += [f"unknown statusReportingSettings key: {k}" for k in sorted(srs) if k not in STATUS_REPORTING_KEYS]
    if len(json.dumps(policy)) > MAX_BYTES:
        errs.append("policy is too large")
    return errs


def diff(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    old = old or {}
    return {
        "added": sorted(k for k in new if k not in old),
        "removed": sorted(k for k in old if k not in new),
        "changed": sorted(k for k in new if k in old and new[k] != old[k]),
    }


def policy_id(name: str, version: int) -> str:
    """AMAPI policy id for one immutable version. Google accepts a bare policy id without slashes in
    devices.patch policyName (checked 2026-10-08); our ids are lowercase letters, digits and hyphens."""
    return f"{name}-v{version}"
