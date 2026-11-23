"""Deterministic test doubles for the context analyzer (used by tests and, later, by runners)."""

from __future__ import annotations

import time
from collections.abc import Sequence

from agentguard.agent.model_adapter import (
    ChatMessage,
    ModelProtocolError,
    ModelResponse,
    ModelToolCall,
    ToolSchema,
    Usage,
)
from agentguard.policy.schemas import AnalyzerVerdict, ContextItem, NormalizedCall, Verdict

VERSION = "double-1"


class FixedAnalyzer:
    """Always returns the configured decision and counts how often it was consulted."""

    def __init__(self, decision: Verdict = Verdict.ALLOW, score: float = 0.0) -> None:
        self.decision = decision
        self.score = score
        self.calls = 0

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict:
        self.calls += 1
        return AnalyzerVerdict(
            decision=self.decision, score=self.score, signals=("fixed",), version=VERSION
        )


class RaisingAnalyzer:
    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict:
        raise RuntimeError("analyzer crashed")


class SlowAnalyzer:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict:
        time.sleep(self.seconds)
        return AnalyzerVerdict(decision=Verdict.ALLOW, score=0.0, version=VERSION)


class MalformedAnalyzer:
    """Returns something that is not an AnalyzerVerdict."""

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> object:
        return {"decision": "ALLOW"}


# ---- model doubles ---------------------------------------------------------------------
class ScriptedModel:
    """Replays a fixed script of responses/exceptions and records what it was shown."""

    model_id = "scripted"
    params: dict[str, object] = {"backend": "scripted"}  # noqa: RUF012 - read-only metadata

    def __init__(self, script: Sequence[ModelResponse | Exception]) -> None:
        self._script = list(script)
        self.seen: list[list[ChatMessage]] = []
        self.tools_seen: list[tuple[str, ...]] = []

    def digest(self) -> str | None:
        return None

    def chat(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSchema], *, timeout_s: float
    ) -> ModelResponse:
        self.seen.append(list(messages))
        self.tools_seen.append(tuple(t.name for t in tools))
        if not self._script:
            raise ModelProtocolError("script exhausted")
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def text_response(text: str, *, tokens_in: int = 10, tokens_out: int = 5) -> ModelResponse:
    return ModelResponse(
        content=text,
        usage=Usage(input_tokens=tokens_in, output_tokens=tokens_out),
        finish_reason="stop",
    )


def tool_response(
    *calls: tuple[str, object], tokens_in: int = 10, tokens_out: int = 5
) -> ModelResponse:
    return ModelResponse(
        tool_calls=tuple(
            ModelToolCall(id=f"c{i}", name=name, arguments=args)
            for i, (name, args) in enumerate(calls)
        ),
        usage=Usage(input_tokens=tokens_in, output_tokens=tokens_out),
        finish_reason="tool_calls",
    )
