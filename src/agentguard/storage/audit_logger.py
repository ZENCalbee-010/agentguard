"""Append-only, hash-chained audit log in SQLite (SEC-010, REQ-AUD-1).

Each record's hash covers the previous hash, so editing or deleting any earlier record
makes :meth:`AuditLogger.verify_chain` fail. This detects tampering after the fact; it does
not prevent a privileged attacker with write access from rewriting the whole chain.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentguard.policy.schemas import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    task_id TEXT,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
)
"""


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: float
    kind: str
    task_id: str | None
    payload: dict[str, Any]
    prev_hash: str
    hash: str


def _record_hash(
    seq: int, ts: float, kind: str, task_id: str | None, payload: str, prev: str
) -> str:
    return sha256_hex(canonical_json([seq, ts, kind, task_id, payload, prev]))


class AuditLogger:
    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()
        self._clock = clock

    def append(self, kind: str, task_id: str | None, payload: dict[str, Any]) -> int:
        body = canonical_json(payload)
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS_HASH)
            ts = float(self._clock())
            h = _record_hash(seq, ts, kind, task_id, body, prev)
            self._conn.execute(
                "INSERT INTO audit (seq, ts, kind, task_id, payload, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, ts, kind, task_id, body, prev, h),
            )
            self._conn.commit()
        return seq

    def records(self, kind: str | None = None) -> list[AuditRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, kind, task_id, payload, prev_hash, hash FROM audit ORDER BY seq"
            ).fetchall()
        out = [AuditRecord(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6]) for r in rows]
        return [r for r in out if kind is None or r.kind == kind]

    def verify_chain(self) -> bool:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, kind, task_id, payload, prev_hash, hash FROM audit ORDER BY seq"
            ).fetchall()
        prev = GENESIS_HASH
        expected_seq = 1
        for seq, ts, kind, task_id, payload, prev_hash, h in rows:
            if seq != expected_seq or prev_hash != prev:
                return False
            if _record_hash(seq, ts, kind, task_id, payload, prev_hash) != h:
                return False
            prev = h
            expected_seq += 1
        return True

    def close(self) -> None:
        with self._lock:
            self._conn.close()
