"""Regression tests for confirmed defects (each names the finding)."""

from __future__ import annotations

import pytest

from agentguard.errors import NormalizationError
from agentguard.normalize import normalize_amount
from agentguard.policy.schemas import GatewayMode, ReasonCode
from agentguard.testing.builders import call


@pytest.mark.regression
def test_rf001_huge_exponent_amount_is_a_normalization_error_not_a_crash() -> None:
    """RF-001: '1e400' made Decimal.quantize raise InvalidOperation out of the normalizer."""
    with pytest.raises(NormalizationError):
        normalize_amount("1e400")


@pytest.mark.regression
def test_rf001_gateway_denies_instead_of_crashing_on_unexpected_validation_failure(make) -> None:  # type: ignore[no-untyped-def]
    """RF-001 (defence in depth): any exception while validating a call must yield DENY."""
    stack, task = make(GatewayMode.B0)

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("simulated registry bug")

    stack.gateway.registry.validate = boom  # type: ignore[method-assign]
    out = stack.step(task, call("get_balance"))
    assert not out.decision.allowed and out.decision.reasons == (ReasonCode.INVALID_CALL,)
    assert out.result is None


@pytest.mark.regression
def test_rf003_registry_rejections_are_not_counted_as_defense_denials() -> None:
    """RF-003: a malformed model call (INVALID_CALL) was counted as a false-positive denial,
    inflating benign false-positive rates and showing 'denials' even in B0 (no defense)."""
    from agentguard.evaluation.metrics import compute_metrics
    from agentguard.evaluation.records import ExperimentRecord, ModelInfo, ToolAttempt

    def rec(reasons: tuple[str, ...]) -> ExperimentRecord:
        return ExperimentRecord(
            experiment_id="x", run_id="r", case_id="c|benign", task_id="c", benchmark="b",
            benchmark_version="1", model=ModelInfo(model_id="m"), config_id="B0", policy_hash="h",
            seed=0, task_success=True, run_status="completed", latency_s=1.0, input_tokens=1,
            output_tokens=1, model_calls=1,
            tool_attempts=(ToolAttempt(step=1, tool="t", verdict="DENY", reasons=reasons, executed=False),),
        )  # fmt: skip

    invalid = compute_metrics([rec(("INVALID_CALL",))])
    assert (
        invalid["benign_cases_with_denial"] == 0 and invalid["benign_cases_with_invalid_call"] == 1
    )
    assert invalid["denials_by_reason"] == {}
    real = compute_metrics([rec(("NO_CAPABILITY",))])
    assert real["benign_cases_with_denial"] == 1 and real["denials_by_reason"] == {
        "NO_CAPABILITY": 1
    }
