"""Typed data structures for calls, policies, decisions and analyzer I/O."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.errors import InvalidCallError

_FROZEN = ConfigDict(frozen=True, extra="forbid")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for every hash in the system."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class GatewayMode(StrEnum):
    """The four experimental configurations (docs/spec/architecture.md §4)."""

    B0 = "B0"  # no analyzer, no policy enforcement
    B1 = "B1"  # analyzer only
    B2 = "B2"  # policy only
    P1 = "P1"  # policy, then analyzer


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ReasonCode(StrEnum):
    # denials
    INVALID_CALL = "INVALID_CALL"
    TASK_NOT_ACTIVE = "TASK_NOT_ACTIVE"
    NO_CAPABILITY = "NO_CAPABILITY"  # no allow-capability exists for the tool
    NO_MATCHING_RULE = "NO_MATCHING_RULE"  # capability exists, call is outside its constraints
    EXPLICIT_DENY = "EXPLICIT_DENY"
    MAX_CALLS_EXCEEDED = "MAX_CALLS_EXCEEDED"
    POLICY_ERROR = "POLICY_ERROR"
    ANALYZER_DENY = "ANALYZER_DENY"
    ANALYZER_ERROR = "ANALYZER_ERROR"
    ANALYZER_TIMEOUT = "ANALYZER_TIMEOUT"
    # allows
    ALLOWED_UNENFORCED = "ALLOWED_UNENFORCED"  # B0
    ALLOWED_BY_POLICY = "ALLOWED_BY_POLICY"  # B2
    ALLOWED_BY_ANALYZER = "ALLOWED_BY_ANALYZER"  # B1
    ALLOWED_BY_POLICY_AND_ANALYZER = "ALLOWED_BY_POLICY_AND_ANALYZER"  # P1


class ToolCall(BaseModel):
    """A tool call exactly as proposed by the model: untrusted, unvalidated."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def parse(cls, obj: object) -> ToolCall:
        """Build from arbitrary model output, mapping every failure to InvalidCallError."""
        if isinstance(obj, ToolCall):
            return obj
        try:
            return cls.model_validate(obj)
        except Exception as exc:
            raise InvalidCallError(
                "proposed call is not a well-formed {tool, args} object"
            ) from exc


class NormalizedCall(BaseModel):
    """A call that passed registry validation; all arguments are canonical strings."""

    model_config = _FROZEN

    task_id: str
    call_id: str
    tool: str
    args: dict[str, str]
    raw_args: dict[str, Any]
    protected: bool

    @property
    def call_hash(self) -> str:
        return sha256_hex(
            canonical_json({"task": self.task_id, "tool": self.tool, "args": self.args})
        )


class ContextItem(BaseModel):
    """A piece of data the model has seen that is not the trusted user prompt."""

    model_config = _FROZEN

    text: str
    source: str
    trust: Trust = Trust.UNTRUSTED

    @field_validator("trust")
    @classmethod
    def _must_be_untrusted(cls, v: Trust) -> Trust:
        if v is not Trust.UNTRUSTED:
            raise ValueError("context items from tools/documents are always untrusted (SEC-009)")
        return v


class Constraint(BaseModel):
    """Exactly one predicate over a single normalized argument."""

    model_config = _FROZEN

    equals: str | None = None
    one_of: tuple[str, ...] | None = None
    path_prefix: str | None = None
    max_value: Decimal | None = None
    # Explicit, auditable wildcard: "any value of this argument is acceptable". Omitting a
    # constraint is still a DENY (SEC-005); this must be written down on purpose.
    any_value: bool | None = None
    # "The argument must NOT be provided" - for optional parameters the task does not touch.
    absent: bool | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Constraint:
        if self.any_value is False or self.absent is False:
            raise ValueError("any_value and absent may only be true")
        set_fields = [
            n
            for n in ("equals", "one_of", "path_prefix", "max_value", "any_value", "absent")
            if getattr(self, n) is not None
        ]
        if len(set_fields) != 1:
            raise ValueError("a constraint must set exactly one predicate")
        if self.one_of is not None and len(self.one_of) == 0:
            raise ValueError("one_of must not be empty")
        return self


class Capability(BaseModel):
    """Permission (or explicit prohibition) for one tool, scoped by argument constraints."""

    model_config = _FROZEN

    tool: str
    effect: Literal["allow", "deny"] = "allow"
    constraints: dict[str, Constraint] = Field(default_factory=dict)
    max_calls: int | None = Field(default=None, ge=1)

    @property
    def cap_id(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))[:16]


class Policy(BaseModel):
    model_config = _FROZEN

    version: str = "1"
    capabilities: tuple[Capability, ...] = ()

    @property
    def policy_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


class TrustedTaskContext(BaseModel):
    """Immutable binding of a task identity to its prompt and policy (SEC-007)."""

    model_config = _FROZEN

    task_id: str
    user_prompt: str
    policy_hash: str


class AnalyzerVerdict(BaseModel):
    model_config = _FROZEN

    decision: Verdict
    score: float = Field(ge=0.0, le=1.0)
    signals: tuple[str, ...] = ()
    version: str


class Decision(BaseModel):
    """Gateway output. ``mac`` binds it to (decision, task, call) so it cannot be forged."""

    model_config = _FROZEN

    decision_id: str
    task_id: str
    call_hash: str
    mode: GatewayMode
    verdict: Verdict
    reasons: tuple[ReasonCode, ...]
    capability_id: str | None = None
    analyzer: AnalyzerVerdict | None = None
    mac: str

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW
