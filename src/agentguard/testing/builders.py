"""Small helpers for writing policies and proposed calls compactly."""

from __future__ import annotations

from decimal import Decimal

from agentguard.policy.schemas import Capability, Constraint, Policy, ToolCall


def eq(value: str) -> Constraint:
    return Constraint(equals=value)


def one_of(*values: str) -> Constraint:
    return Constraint(one_of=tuple(values))


def prefix(path: str) -> Constraint:
    return Constraint(path_prefix=path)


def at_most(value: str | int | float) -> Constraint:
    return Constraint(max_value=Decimal(str(value)))


def anything() -> Constraint:
    """Explicit wildcard for an argument the task text does not determine."""
    return Constraint(any_value=True)


def absent() -> Constraint:
    """The (optional) argument must not be provided."""
    return Constraint(absent=True)


def allow(tool: str, *, max_calls: int | None = None, **constraints: Constraint) -> Capability:
    return Capability(tool=tool, effect="allow", constraints=constraints, max_calls=max_calls)


def deny(tool: str, **constraints: Constraint) -> Capability:
    return Capability(tool=tool, effect="deny", constraints=constraints)


def policy(*caps: Capability) -> Policy:
    return Policy(capabilities=tuple(caps))


def call(tool: str, **args: object) -> ToolCall:
    return ToolCall(tool=tool, args=dict(args))
