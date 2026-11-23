"""Normalizers for benchmark-style parameters and the `absent` constraint (M6 adapter work)."""

from __future__ import annotations

import pytest

from agentguard.agent.tool_registry import ParamSpec, ParamType, ToolRegistry, ToolSpec
from agentguard.errors import NormalizationError, PolicyError
from agentguard.normalize import (
    normalize_account,
    normalize_bool,
    normalize_integer,
    normalize_relpath,
)
from agentguard.policy.capability_store import normalize_capability
from agentguard.policy.policy_engine import PolicyEngine
from agentguard.policy.schemas import Constraint, ReasonCode, ToolCall, Verdict
from agentguard.testing.builders import absent, allow, anything, eq

UPD = ToolSpec(
    name="update_order",
    protected=True,
    params={
        "id": ParamSpec(type=ParamType.INTEGER, security_relevant=True),
        "recipient": ParamSpec(type=ParamType.ACCOUNT, required=False, security_relevant=True),
        "amount": ParamSpec(type=ParamType.AMOUNT, required=False, security_relevant=True),
        "recurring": ParamSpec(type=ParamType.BOOL, required=False),
    },
)
REG = ToolRegistry([UPD])
ENGINE = PolicyEngine(REG)


def _eval(cap, **args):  # type: ignore[no-untyped-def]
    call = REG.validate(ToolCall(tool="update_order", args=args), "t")
    return ENGINE.evaluate([normalize_capability(cap, REG)], call, {})


@pytest.mark.parametrize(
    ("raw", "out"), [(7, "7"), ("7", "7"), (" 12 ", "12"), (3.0, "3"), (0, "0")]
)
def test_integer_ok(raw: object, out: str) -> None:
    assert normalize_integer(raw) == out


@pytest.mark.parametrize("raw", [True, -1, 1.5, "1.5", "abc", "", "٣", 10**10, None, [1]])
def test_integer_rejects(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_integer(raw)


def test_bool() -> None:
    assert [normalize_bool(v) for v in (True, False, "True", " false ")] == [
        "true",
        "false",
        "true",
        "false",
    ]
    for bad in (1, 0, "yes", None, "1"):
        with pytest.raises(NormalizationError):
            normalize_bool(bad)


@pytest.mark.parametrize(
    ("raw", "out"),
    [
        ("bill-december-2023.txt", "bill-december-2023.txt"),
        ("./a//b.txt", "a/b.txt"),
        ("dir\\f.txt", "dir/f.txt"),
        ("%62ill.txt", "bill.txt"),
    ],
)
def test_relpath_ok(raw: str, out: str) -> None:
    assert normalize_relpath(raw) == out


@pytest.mark.parametrize(
    "raw",
    [
        "/etc/passwd",
        "../secret.txt",
        "a/../../b",
        "%2e%2e/x",
        "%252e%252e/x",
        "",
        ".",
        "a\x00b",
        None,
    ],
)
def test_relpath_rejects_traversal_absolute_and_garbage(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_relpath(raw)


@pytest.mark.parametrize(
    ("raw", "out"),
    [
        ("us13 3000 0001 2121 2121 212", "US133000000121212121212"),
        ("GB29-NWBK-6016-1331-9268-19", "GB29NWBK60161331926819"),
        ("Spotify", "spotify"),
        ("  Apple   Inc ", "apple inc"),
    ],
)
def test_account_iban_or_payee_name(raw: str, out: str) -> None:
    assert normalize_account(raw) == out


@pytest.mark.parametrize("raw", ["", "   ", "x" * 65, chr(0x430) + "pple", "a\nb", "a\tb", None, 5])
def test_account_rejects(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_account(raw)


def test_payee_name_cannot_impersonate_an_iban_or_vice_versa() -> None:
    assert (
        normalize_account("SPOTIFY")
        == normalize_account("spotify")
        != normalize_account("US133000000121212121212")
    )


# ---- absent / optional parameter semantics -----------------------------------------------------
def test_absent_allows_calls_that_leave_the_parameter_out_and_blocks_those_that_set_it() -> None:
    cap = allow("update_order", id=anything(), recipient=absent(), amount=anything())
    assert _eval(cap, id=7, amount=1200).verdict is Verdict.ALLOW  # rent amount change only
    redirected = _eval(cap, id=7, amount=1200, recipient="US133000000121212121212")
    assert (redirected.verdict, redirected.reason) == (Verdict.DENY, ReasonCode.NO_MATCHING_RULE)


def test_security_relevant_optional_parameter_still_needs_a_constraint() -> None:
    cap = allow("update_order", id=anything(), amount=anything())  # recipient never mentioned
    assert _eval(cap, id=7, amount=1).reason is ReasonCode.NO_MATCHING_RULE


def test_equals_on_an_omitted_optional_parameter_does_not_match() -> None:
    cap = allow("update_order", id=anything(), recipient=eq("spotify"), amount=anything())
    assert _eval(cap, id=7, amount=1).verdict is Verdict.DENY  # strict: absent != "spotify"
    assert _eval(cap, id=7, amount=1, recipient="Spotify").verdict is Verdict.ALLOW


def test_absent_on_a_required_parameter_is_a_policy_error_and_validation() -> None:
    with pytest.raises(PolicyError):
        normalize_capability(
            allow("update_order", id=absent(), recipient=absent(), amount=absent()), REG
        )
    with pytest.raises(ValueError, match="only be true"):
        Constraint(absent=False)
    with pytest.raises(ValueError, match="exactly one"):
        Constraint(absent=True, any_value=True)


def test_call_validation_with_new_types() -> None:
    call = REG.validate(
        ToolCall(
            tool="update_order", args={"id": "7", "recurring": "True", "recipient": " Spotify"}
        ),
        "t",
    )
    assert call.args == {"id": "7", "recurring": "true", "recipient": "spotify"}
    from agentguard.errors import InvalidCallError

    with pytest.raises(InvalidCallError):
        REG.validate(ToolCall(tool="update_order", args={"id": -1}), "t")
