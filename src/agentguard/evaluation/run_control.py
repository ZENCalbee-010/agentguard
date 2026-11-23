"""Run control for long experiments: what to (re-)run, and when to stop (M8 plan, section 8).

Two failure kinds are kept apart. A *model-behaviour* status (step limit, context overflow, a limit
reached) is a legitimate outcome of the case and is never re-run. An *infrastructure* status (the
model server timed out or errored) says nothing about the defense, so such a case is re-run once
more; every attempt stays in the data and the analysis uses the latest one per case.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from agentguard.errors import AgentGuardError
from agentguard.evaluation.records import ExperimentRecord

INFRA_STATUSES = frozenset({"model_timeout", "model_error"})
MAX_ATTEMPTS = 2  # first attempt plus one re-run
CONSECUTIVE_INFRA_LIMIT = 3  # abort the run after this many infrastructure failures in a row

CaseKey = tuple[str, str]  # (config_id, case_id)


class InfraAbort(AgentGuardError):
    """Raised when the model server appears to be down; the run stops instead of writing junk."""


def infra_failed(record: ExperimentRecord) -> bool:
    return record.run_status in INFRA_STATUSES


def attempts_by_case(records: Iterable[ExperimentRecord]) -> dict[CaseKey, list[ExperimentRecord]]:
    """All attempts per (config, case), in file order (the order they were written)."""
    out: dict[CaseKey, list[ExperimentRecord]] = {}
    for r in records:
        out.setdefault((r.config_id, r.case_id), []).append(r)
    return out


def latest_per_case(records: Iterable[ExperimentRecord]) -> dict[CaseKey, ExperimentRecord]:
    """The record the analysis uses for each case: the last attempt written."""
    return {k: v[-1] for k, v in attempts_by_case(records).items()}


def plan_todo(
    expected: Sequence[CaseKey], records: Iterable[ExperimentRecord]
) -> tuple[list[CaseKey], list[CaseKey]]:
    """Cases to run now, and cases whose every attempt failed for infrastructure reasons.

    A case with no record runs. A case whose records are all infrastructure failures runs again
    until ``MAX_ATTEMPTS`` attempts exist; after that it is reported as exhausted and left alone.
    A case that has any other record is finished, whatever its status.
    """
    seen = attempts_by_case(records)
    todo: list[CaseKey] = []
    exhausted: list[CaseKey] = []
    for key in expected:
        rs = seen.get(key, [])
        if not rs:
            todo.append(key)
        elif all(infra_failed(r) for r in rs):
            (todo if len(rs) < MAX_ATTEMPTS else exhausted).append(key)
    return todo, exhausted


class InfraGuard:
    """Counts consecutive infrastructure failures and aborts before a crash fills the file."""

    def __init__(self, limit: int = CONSECUTIVE_INFRA_LIMIT) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self._limit = limit
        self._streak = 0

    def observe(self, record: ExperimentRecord) -> None:
        self._streak = self._streak + 1 if infra_failed(record) else 0
        if self._streak >= self._limit:
            raise InfraAbort(
                f"{self._streak} consecutive infrastructure failures "
                f"(last status {record.run_status}); the model server is probably down"
            )
