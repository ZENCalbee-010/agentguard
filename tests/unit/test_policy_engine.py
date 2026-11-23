from __future__ import annotations

import pytest

from agentguard.agent.tool_registry import default_registry
from agentguard.errors import PolicyError
from agentguard.policy.capability_store import TrustedChannel, normalize_capability
from agentguard.policy.policy_engine import PolicyEngine
from agentguard.policy.schemas import Constraint, NormalizedCall, ReasonCode, ToolCall, Verdict
from agentguard.testing.builders import allow, at_most, call, deny, eq, one_of, prefix

REG = default_registry()
ENGINE = PolicyEngine(REG)


def _norm(c: object) -> NormalizedCall:
    assert isinstance(c, ToolCall)
    return REG.validate(c, "t1")


def _eval(caps: list, c: ToolCall, usage: dict | None = None):  # type: ignore[type-arg]
    return ENGINE.evaluate([normalize_capability(x, REG) for x in caps], _norm(c), usage or {})


SEND = call("send_money", recipient_iban="UK12 3456 7890 1234 5678 90", amount=50, subject="bill")


def test_empty_policy_denies_with_no_capability() -> None:
    v = _eval([], SEND)
    assert (v.verdict, v.reason) == (Verdict.DENY, ReasonCode.NO_CAPABILITY)


def test_allow_when_all_security_args_constrained_and_met() -> None:
    cap = allow("send_money", recipient_iban=eq("uk12345678901234567890"), amount=at_most(100))
    v = _eval([cap], SEND)
    assert v.verdict is Verdict.ALLOW and v.capability_id == normalize_capability(cap, REG).cap_id


def test_missing_constraint_on_security_relevant_arg_does_not_match() -> None:
    cap = allow("send_money", recipient_iban=eq("UK12345678901234567890"))  # amount unconstrained
    v = _eval([cap], SEND)
    assert (v.verdict, v.reason) == (Verdict.DENY, ReasonCode.NO_MATCHING_RULE)


def test_constraint_violation_is_no_matching_rule() -> None:
    cap = allow("send_money", recipient_iban=eq("UK12345678901234567890"), amount=at_most(10))
    v = _eval([cap], SEND)
    assert (v.verdict, v.reason) == (Verdict.DENY, ReasonCode.NO_MATCHING_RULE)


def test_amount_boundary_is_inclusive() -> None:
    cap = allow("send_money", recipient_iban=eq("UK12345678901234567890"), amount=at_most("50.00"))
    assert _eval([cap], SEND).verdict is Verdict.ALLOW
    over = call("send_money", recipient_iban="UK12345678901234567890", amount="50.01", subject="x")
    assert _eval([cap], over).verdict is Verdict.DENY


def test_explicit_deny_overrides_matching_allow() -> None:
    caps = [
        allow("send_money", recipient_iban=eq("UK12345678901234567890"), amount=at_most(100)),
        deny("send_money", recipient_iban=eq("UK12345678901234567890")),
    ]
    v = _eval(caps, SEND)
    assert (v.verdict, v.reason) == (Verdict.DENY, ReasonCode.EXPLICIT_DENY)


def test_deny_order_does_not_matter() -> None:
    a = allow("get_balance")
    d = deny("get_balance")
    for caps in ([a, d], [d, a]):
        assert _eval(caps, call("get_balance")).reason is ReasonCode.EXPLICIT_DENY


def test_non_matching_deny_does_not_block() -> None:
    caps = [
        allow("send_money", recipient_iban=eq("UK12345678901234567890"), amount=at_most(100)),
        deny("send_money", recipient_iban=eq("US133000000121212121212")),
    ]
    assert _eval(caps, SEND).verdict is Verdict.ALLOW


def test_one_of_and_path_prefix() -> None:
    caps = [allow("read_file", path=prefix("/bills"))]
    assert _eval(caps, call("read_file", path="/bills/./dec.txt")).verdict is Verdict.ALLOW
    assert _eval(caps, call("read_file", path="/bills-evil/x")).verdict is Verdict.DENY
    two = [allow("send_email", to=one_of("a@x.com", "B@X.com"))]
    ok = call("send_email", to=" b@x.COM", subject="s", body="b")
    assert _eval(two, ok).verdict is Verdict.ALLOW


def test_max_calls_budget() -> None:
    cap = allow("get_balance", max_calls=2)
    cid = normalize_capability(cap, REG).cap_id
    assert _eval([cap], call("get_balance"), {cid: 1}).verdict is Verdict.ALLOW
    v = _eval([cap], call("get_balance"), {cid: 2})
    assert (v.verdict, v.reason) == (Verdict.DENY, ReasonCode.MAX_CALLS_EXCEEDED)


def test_second_matching_allow_with_budget_is_used() -> None:
    a = allow("get_balance", max_calls=1)
    b = allow("get_balance")
    v = _eval([a, b], call("get_balance"), {normalize_capability(a, REG).cap_id: 1})
    assert v.verdict is Verdict.ALLOW and v.capability_id == normalize_capability(b, REG).cap_id


@pytest.mark.parametrize(
    "bad",
    [
        allow("no_such_tool"),
        allow("send_money", nope=eq("x")),
        allow("send_money", amount=Constraint(path_prefix="/x")),
        allow("send_money", recipient_iban=Constraint(max_value=5)),
        allow("send_money", recipient_iban=eq("not-an-iban")),
    ],
)
def test_malformed_capabilities_are_rejected_at_load(bad: object) -> None:
    with pytest.raises(PolicyError):
        normalize_capability(bad, REG)  # type: ignore[arg-type]


def test_constraint_requires_exactly_one_predicate() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        Constraint(equals="a", one_of=("b",))
    with pytest.raises(ValueError, match="exactly one"):
        Constraint()


def test_trusted_channel_tokens_bind_task_and_capability() -> None:
    ch = TrustedChannel()
    cap = allow("get_balance")
    tok = ch.mint("task-1", cap)
    assert ch.verify("task-1", cap, tok)
    assert not ch.verify("task-2", cap, tok)
    assert not ch.verify("task-1", allow("read_file", path=eq("/a")), tok)
    assert not TrustedChannel().verify("task-1", cap, tok)


# ---- explicit wildcard (any_value) -----------------------------------------------------
def test_any_value_is_an_explicit_wildcard_for_one_argument() -> None:
    from agentguard.testing.builders import anything

    cap = allow("send_money", recipient_iban=anything(), amount=at_most(100))
    other = call("send_money", recipient_iban="US133000000121212121212", amount=50, subject="s")
    assert _eval([cap], other).verdict is Verdict.ALLOW  # any recipient ...
    big = call("send_money", recipient_iban="US133000000121212121212", amount=500, subject="s")
    assert _eval([cap], big).reason is ReasonCode.NO_MATCHING_RULE  # ... but the cap still binds


def test_omitting_a_constraint_is_still_deny_even_though_a_wildcard_exists() -> None:
    cap = allow("send_money", amount=at_most(100))  # recipient neither constrained nor wildcarded
    assert _eval([cap], SEND).reason is ReasonCode.NO_MATCHING_RULE


def test_explicit_deny_beats_wildcard_allow() -> None:
    from agentguard.testing.builders import anything

    caps = [
        allow("send_money", recipient_iban=anything(), amount=anything()),
        deny("send_money", recipient_iban=eq("UK12345678901234567890")),
    ]
    assert _eval(caps, SEND).reason is ReasonCode.EXPLICIT_DENY


def test_any_value_must_be_true_and_exclusive() -> None:
    with pytest.raises(ValueError, match="only be true"):
        Constraint(any_value=False)
    with pytest.raises(ValueError, match="exactly one"):
        Constraint(any_value=True, equals="x")
