"""Experiment record schema (REQ-EVL-2), storage with completeness checks, and CSV export.

Every number reported anywhere must be recomputable from these records. A run that did not end
cleanly keeps its error status and is excluded from rate numerators AND denominators, with the
exclusion counted and reported (REQ-ORC-4); an interrupted run simply has no record and is
reported as a missing case.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "record-1"


class ModelInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    digest: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class ToolAttempt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int
    tool: str
    verdict: str
    reasons: tuple[str, ...]
    executed: bool
    ok: bool | None = None


class ExperimentRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = SCHEMA_VERSION
    experiment_id: str
    run_id: str
    case_id: str  # identifies the case across configurations (pairing key with model, repetition)
    repetition: int = 0
    task_id: str  # user-task cluster
    scenario_id: str | None = None  # None for benign cases
    attack_family: str | None = None
    benchmark: str
    benchmark_version: str
    model: ModelInfo
    config_id: str  # B0 / B1 / B2 / P1
    policy_hash: str
    analyzer_version: str | None = None
    code_commit: str | None = None
    code_dirty: bool = True
    seed: int
    tool_attempts: tuple[ToolAttempt, ...] = ()
    attack_attempted: bool | None = None  # None for benign cases
    attack_executed: bool | None = None  # state oracle
    task_success: bool
    run_status: str  # "completed" or an error/limit status
    latency_s: float
    input_tokens: int
    output_tokens: int
    model_calls: int
    cost_estimate_thb: float = 0.0  # local models: 0
    data_derived: bool | None = None

    @property
    def is_attack(self) -> bool:
        return self.scenario_id is not None

    @property
    def clean(self) -> bool:
        return self.run_status == "completed"

    @property
    def pair_key(self) -> tuple[str, str, int]:
        return (self.model.model_id, self.case_id, self.repetition)


def from_smoke_dict(d: Mapping[str, Any], experiment_id: str) -> ExperimentRecord:
    """Convert an M5 smoke-test raw dict (schema m5-smoke-1) into the formal record."""
    scenario = d.get("scenario_id")
    return ExperimentRecord(
        experiment_id=experiment_id,
        run_id=d["run_id"],
        case_id=f"{d['task_id']}|{scenario or 'benign'}",
        task_id=d["task_id"],
        scenario_id=scenario,
        attack_family=d.get("template"),
        benchmark="own-domain-smoke",
        benchmark_version="v1",
        model=ModelInfo(
            model_id=d["model"], digest=d.get("model_digest"), params=dict(d["model_params"])
        ),
        config_id=d["mode"],
        policy_hash=d["policy_hash"],
        analyzer_version=d.get("analyzer"),
        code_commit=(d.get("code") or {}).get("commit"),
        code_dirty=bool((d.get("code") or {}).get("dirty", True)),
        seed=int(d["model_params"].get("seed", 0)),
        tool_attempts=tuple(
            ToolAttempt(
                step=c["step"],
                tool=c["tool"],
                verdict=c["verdict"],
                reasons=tuple(c["reasons"]),
                executed=c["executed"],
                ok=c.get("ok"),
            )
            for c in d["calls"]
        ),
        attack_attempted=d.get("attempted"),
        attack_executed=d.get("attack_executed"),
        task_success=bool(d["utility"]),
        run_status=d["status"],
        latency_s=float(d["wall_s"]),
        input_tokens=int(d["input_tokens"]),
        output_tokens=int(d["output_tokens"]),
        model_calls=int(d["model_calls"]),
        data_derived=d.get("data_derived"),
    )


def write_records(path: Path, records: Iterable[ExperimentRecord]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(r.model_dump_json() + "\n")
            n += 1
    return n


def read_records(path: Path) -> list[ExperimentRecord]:
    """Strict read: any line that fails the schema raises (no silent skipping)."""
    return [
        ExperimentRecord.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def missing_cases(
    expected: Iterable[tuple[str, str, str, int]], records: Sequence[ExperimentRecord]
) -> list[tuple[str, str, str, int]]:
    """Expected (model, config, case_id, repetition) combinations with no record."""
    have = {(r.model.model_id, r.config_id, r.case_id, r.repetition) for r in records}
    return sorted(set(expected) - have)


CSV_FIELDS = (
    "experiment_id", "run_id", "case_id", "repetition", "task_id", "scenario_id", "attack_family",
    "benchmark", "benchmark_version", "model_id", "model_digest", "config_id", "policy_hash",
    "analyzer_version", "code_commit", "code_dirty", "seed", "attack_attempted", "attack_executed",
    "task_success", "run_status", "latency_s", "input_tokens", "output_tokens", "model_calls",
    "cost_estimate_thb", "n_tool_attempts", "n_denied", "n_executed", "data_derived",
)  # fmt: skip


def export_csv(path: Path, records: Iterable[ExperimentRecord]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in records:
            row = json.loads(r.model_dump_json())
            row.update(
                model_id=r.model.model_id,
                model_digest=r.model.digest,
                n_tool_attempts=len(r.tool_attempts),
                n_denied=sum(1 for a in r.tool_attempts if a.verdict == "DENY"),
                n_executed=sum(1 for a in r.tool_attempts if a.executed),
            )
            w.writerow({k: row.get(k) for k in CSV_FIELDS})
            n += 1
    return n
