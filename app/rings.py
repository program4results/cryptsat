"""Staged rollout. A device's bucket (0-99) is a stable hash of tenant + device id, so rings never reshuffle."""
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
