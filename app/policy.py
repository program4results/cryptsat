"""Policy templates and validation. Only keys in ALLOWED may be sent to Google; field names must be checked
against the AMAPI Policy reference before the first real enrolment (NOT verified in this foundation)."""
from __future__ import annotations

from typing import Any

ALLOWED = {
    "applications", "debuggingFeaturesAllowed", "factoryResetDisabled", "passwordRequirements",
    "statusReportingSettings", "installUnknownSourcesAllowed", "keyguardDisabled",
}
# Phase 1 never sets these: they can lock operators out or destroy data.
FORBIDDEN_VALUES = {("keyguardDisabled", True)}

TEMPLATES: dict[str, dict[str, Any]] = {
    # Minimal baseline. ADB stays allowed so RUSTAiDMIN diagnostics still work (decision to revisit per tenant).
    "baseline": {
        "debuggingFeaturesAllowed": True,
        "statusReportingSettings": {"applicationReportsEnabled": True, "deviceSettingsEnabled": True},
    },
}


def validate(policy: dict[str, Any]) -> list[str]:
    errs = [f"unknown policy key: {k}" for k in policy if k not in ALLOWED]
    errs += [f"forbidden setting: {k}={v}" for k, v in policy.items() if (k, v) in FORBIDDEN_VALUES]
    return errs


def diff(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    old = old or {}
    return {
        "added": sorted(k for k in new if k not in old),
        "removed": sorted(k for k in old if k not in new),
        "changed": sorted(k for k in new if k in old and new[k] != old[k]),
    }
