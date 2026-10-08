"""Append-only, hash-chained audit log. Each record commits to the previous one, so edits or deletions are detectable."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(rec: dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if path and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.records.append(json.loads(line))

    def append(self, actor: str, tenant: str | None, action: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            prev = self.records[-1]["hash"] if self.records else GENESIS
            rec: dict[str, Any] = {
                "seq": len(self.records) + 1,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "actor": actor,
                "tenant": tenant,
                "action": action,
                "detail": detail or {},
                "prev": prev,
            }
            rec["hash"] = _digest(rec)
            self.records.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            return rec

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if the whole chain is intact, else (False, first bad seq)."""
        prev = GENESIS
        for i, rec in enumerate(self.records, start=1):
            if rec.get("seq") != i or rec.get("prev") != prev or rec.get("hash") != _digest(rec):
                return False, i
            prev = rec["hash"]
        return True, None

    def tail(self, tenant: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        rows = [r for r in self.records if tenant is None or r["tenant"] == tenant]
        return rows[-max(1, min(limit, 500)):][::-1]
