"""Run control (M8 plan section 8): which cases to (re-)run and when to stop."""

from __future__ import annotations

import pytest

from agentguard.errors import AgentGuardError
from agentguard.evaluation.records import ExperimentRecord
from agentguard.evaluation.run_control import (
    InfraAbort,
    InfraGuard,
    attempts_by_case,
    infra_failed,
    latest_per_case,
    plan_todo,
)


def rec(config: str, case: str, status: str = "completed") -> ExperimentRecord:
    return ExperimentRecord.model_validate(
        {
            "experiment_id": "x", "run_id": f"{config}{case}{status}", "case_id": case,
            "task_id": case.split("|")[0], "benchmark": "b", "benchmark_version": "1",
            "model": {"model_id": "m"}, "config_id": config, "policy_hash": "h", "seed": 0,
            "task_success": status == "completed", "run_status": status, "latency_s": 1.0,
            "input_tokens": 1, "output_tokens": 1, "model_calls": 1,
        }
    )  # fmt: skip


EXPECTED = [("B0", "u0|benign"), ("B0", "u1|benign"), ("B2", "u0|benign")]


def test_nothing_recorded_runs_everything() -> None:
    assert plan_todo(EXPECTED, []) == (EXPECTED, [])


def test_finished_cases_are_skipped_whatever_their_status() -> None:
    # behaviour outcomes (step limit, context overflow) are results, not failures to retry
    recs = [
        rec("B0", "u0|benign"),
        rec("B0", "u1|benign", "step_limit"),
        rec("B2", "u0|benign", "context_overflow"),
    ]
    assert plan_todo(EXPECTED, recs) == ([], [])


def test_infrastructure_failures_are_retried_once_and_then_left_alone() -> None:
    first = [rec("B0", "u0|benign", "model_error")]
    todo, exhausted = plan_todo(EXPECTED, first)
    assert ("B0", "u0|benign") in todo and not exhausted
    second = [*first, rec("B0", "u0|benign", "model_timeout")]
    todo, exhausted = plan_todo(EXPECTED, second)
    assert ("B0", "u0|benign") not in todo and exhausted == [("B0", "u0|benign")]
    # a successful re-run closes the case
    healed = [*first, rec("B0", "u0|benign")]
    assert ("B0", "u0|benign") not in plan_todo(EXPECTED, healed)[0]


def test_latest_attempt_wins_and_all_attempts_are_kept() -> None:
    a, b = rec("B0", "u0|benign", "model_error"), rec("B0", "u0|benign")
    assert latest_per_case([a, b])[("B0", "u0|benign")] is b
    assert attempts_by_case([a, b])[("B0", "u0|benign")] == [a, b]
    assert infra_failed(a) and not infra_failed(b)


def test_guard_aborts_after_consecutive_infrastructure_failures_only() -> None:
    guard = InfraGuard(limit=3)
    for status in ("model_error", "model_timeout", "completed", "model_error", "model_error"):
        guard.observe(rec("B0", "u0|benign", status))  # the success in the middle resets the streak
    with pytest.raises(InfraAbort):
        guard.observe(rec("B0", "u0|benign", "model_error"))
    assert issubclass(InfraAbort, AgentGuardError)
    with pytest.raises(ValueError):
        InfraGuard(limit=0)
