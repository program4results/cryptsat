"""Staged rollout. A device's bucket (0-99) is a stable hash of tenant + device id, so rings never reshuffle,
and each ring contains the previous one (pilot devices are always included)."""
from __future__ import annotations

import hashlib

STAGES = ("pilot", "r5", "r25", "r100")
LIMIT = {"pilot": 0, "r5": 5, "r25": 25, "r100": 100}


def bucket(tenant_id: str, device_id: str) -> int:
    return int(hashlib.sha256(f"{tenant_id}/{device_id}".encode()).hexdigest(), 16) % 100


def selected(tenant_id: str, device_id: str, stage: str, pilot: set[str]) -> bool:
    if stage not in LIMIT:
        raise ValueError("unknown stage")
    if device_id in pilot:
        return True
    return bucket(tenant_id, device_id) < LIMIT[stage]


def is_forward(current: str, new: str) -> bool:
    return STAGES.index(new) > STAGES.index(current)


def next_stage(current: str) -> str | None:
    i = STAGES.index(current)
    return STAGES[i + 1] if i + 1 < len(STAGES) else None
