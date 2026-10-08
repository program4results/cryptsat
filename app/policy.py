"""Policy templates and validation. Only top-level keys in ALLOWED may be sent to Google.

Checked on 2026-10-08 against the AMAPI Policy reference: every key in ALLOWED exists on the Policy resource.
NOT verified yet: whether debuggingFeaturesAllowed and installUnknownSourcesAllowed are deprecated in favour of
advancedSecurityOverrides, and the subfield names inside statusReportingSettings used by the baseline template.
Confirm both before the first real enrolment.
"""
from __future__ import annotations

import json
from typing import Any

ALLOWED = frozenset({
    "applications", "debuggingFeaturesAllowed", "factoryResetDisabled", "passwordRequirements",
    "statusReportingSettings", "installUnknownSourcesAllowed", "keyguardDisabled", "advancedSecurityOverrides",
})
# Phase 1 never sets these: they can lock operators out or remove the device from management.
FORBIDDEN_VALUES: dict[str, Any] = {"keyguardDisabled": True}
MAX_BYTES = 256 * 1024

TEMPLATES: dict[str, dict[str, Any]] = {
    # Minimal baseline. ADB stays allowed so RUSTAiDMIN diagnostics still work (documented exception).
    "baseline": {
        "debuggingFeaturesAllowed": True,
        "installUnknownSourcesAllowed": False,
        "statusReportingSettings": {"applicationReportsEnabled": True, "deviceSettingsEnabled": True},
    },
}


def validate(policy: dict[str, Any]) -> list[str]:
    if not isinstance(policy, dict) or not policy:
        return ["policy must be a non-empty object"]
    errs = [f"unknown policy key: {k}" for k in sorted(policy) if k not in ALLOWED]
    errs += [f"forbidden setting: {k}={v!r}" for k, v in sorted(policy.items())
             if k in FORBIDDEN_VALUES and v == FORBIDDEN_VALUES[k]]
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
    """AMAPI policy id for one immutable version. Allowed id characters NOT verified with Google yet."""
    return f"{name}-v{version}"
