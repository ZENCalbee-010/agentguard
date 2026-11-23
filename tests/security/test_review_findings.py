"""Tests added by the M3 self-review (docs/milestones/M3-report.md, section Self-review).

Each test pins a property that was reasoned about during review and could silently regress.
"""

from __future__ import annotations

import pytest

from agentguard.errors import NormalizationError, UnauthorizedExecution
from agentguard.normalize import normalize_email, normalize_iban
from agentguard.policy.schemas import GatewayMode
from agentguard.sandbox.state import state_diff
from agentguard.testing.builders import allow, at_most, call, eq
from conftest import ATTACKER_IBAN, BILL_IBAN

pytestmark = pytest.mark.security
PAY_BILL = allow("send_money", recipient_iban=eq(BILL_IBAN), amount=at_most(200))
SHARP_S = chr(0xDF)  # str.upper() turns this into "SS"
DOTTED_CAPITAL_I = chr(0x130)  # str.lower() turns this into "i" + combining dot
KELVIN_SIGN = chr(0x212A)  # str.lower() turns this into ASCII "k"


def test_rv001_mutating_an_authorized_call_before_execution_is_refused(make) -> None:  # type: ignore[no-untyped-def]
    """TOCTOU: the call hash is recomputed from the call's current arguments at execution."""
    stack, task = make(GatewayMode.B2, PAY_BILL)
    res = stack.gateway.authorize(
        task, call("send_money", recipient_iban=BILL_IBAN, amount=10, subject="s")
    )
    assert res.call is not None and res.decision.allowed
    before = stack.state.snapshot()
    res.call.args["recipient_iban"] = ATTACKER_IBAN  # attacker-influenced code edits the dict
    with pytest.raises(UnauthorizedExecution):
        stack.executor.execute(res.call, res.decision)
    assert state_diff(before, stack.state) == {}


def test_rv002_iban_with_case_expanding_character_is_rejected_not_rewritten() -> None:
    """RF-002: an IBAN containing a sharp s used to be silently rewritten to '...SS...'."""
    with pytest.raises(NormalizationError):
        normalize_iban("US13" + SHARP_S + "000000121212121212")
    assert normalize_iban("US13SS000000121212121212") == "US13SS000000121212121212"


def test_rv002_email_with_unicode_that_lowercases_into_ascii_is_rejected() -> None:
    """The Kelvin sign lower-cases to ASCII 'k'; without an ASCII check a look-alike would pass."""
    with pytest.raises(NormalizationError):
        normalize_email(KELVIN_SIGN + "@example.com")
    with pytest.raises(NormalizationError):
        normalize_email(DOTTED_CAPITAL_I + "@example.com")
    assert normalize_email("K@Example.com") == "k@example.com"
