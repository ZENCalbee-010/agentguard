"""Unit tests for STRING_LIST and EMAIL_LIST normalizers and optional-None handling."""

from __future__ import annotations

import pytest

from agentguard.agent.tool_registry import ParamSpec, ParamType, ToolRegistry, ToolSpec
from agentguard.errors import InvalidCallError, NormalizationError
from agentguard.normalize import normalize_email_list, normalize_string_list
from agentguard.policy.schemas import ToolCall


def test_normalize_email_list_canonicalizes_and_dedupes() -> None:
    assert (
        normalize_email_list(["  JaneLong@Google.COM ", "alice@example.com", "janelong@google.com"])
        == '["alice@example.com","janelong@google.com"]'
    )
    assert normalize_email_list('["JaneLong@google.com"]') == '["janelong@google.com"]'


def test_normalize_email_list_rejects_empty_or_non_ascii_or_malformed() -> None:
    for bad in ([], ["not-an-email"], ["\u212a@example.com"], "alice@example.com", 123):
        with pytest.raises(NormalizationError):
            normalize_email_list(bad)


def test_normalize_string_list_preserves_order_and_rejects_bad_types() -> None:
    assert normalize_string_list(["Hotel A", "Hotel B"]) == '["Hotel A","Hotel B"]'
    assert normalize_string_list([]) == "[]"
    with pytest.raises(NormalizationError):
        normalize_string_list(["ok", 42])


def test_optional_none_is_omitted_while_required_none_is_rejected() -> None:
    reg = ToolRegistry(
        [
            ToolSpec(
                name="send_email",
                params={
                    "recipients": ParamSpec(type=ParamType.EMAIL_LIST, security_relevant=True),
                    "cc": ParamSpec(
                        type=ParamType.EMAIL_LIST, required=False, security_relevant=True
                    ),
                },
                protected=True,
            )
        ]
    )
    ok = reg.validate(
        ToolCall(tool="send_email", args={"recipients": ["JaneLong@google.com"], "cc": None}),
        "t1",
    )
    assert ok.args == {"recipients": '["janelong@google.com"]'}
    with pytest.raises(InvalidCallError):
        reg.validate(ToolCall(tool="send_email", args={"recipients": None}), "t1")
