"""Deterministic, deny-by-default capability evaluation (SEC-005, SEC-006, SEC-012).

``PolicyEngine.evaluate`` deliberately takes no untrusted context: the only inputs are the
granted capabilities, the validated call and usage counters (SEC-009).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal

from agentguard.agent.tool_registry import ToolRegistry
from agentguard.errors import PolicyError
from agentguard.normalize import path_is_within
from agentguard.policy.schemas import Capability, Constraint, NormalizedCall, ReasonCode, Verdict


@dataclass(frozen=True)
class PolicyVerdict:
    verdict: Verdict
    reason: ReasonCode
    capability_id: str | None = None


def _satisfies(constraint: Constraint, value: str) -> bool:
    if constraint.any_value:
        return True
    if constraint.equals is not None:
        return value == constraint.equals
    if constraint.one_of is not None:
        return value in constraint.one_of
    if constraint.path_prefix is not None:
        return path_is_within(value, constraint.path_prefix)
    if constraint.max_value is not None:
        return Decimal(value) <= Decimal(constraint.max_value)
    raise PolicyError("constraint has no predicate")  # unreachable: validated at construction


class PolicyEngine:
    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def _constraints_hold(self, cap: Capability, call: NormalizedCall) -> bool:
        for pname, constraint in cap.constraints.items():
            value = call.args.get(pname)
            if constraint.absent:  # must not be provided
                if value is not None:
                    return False
                continue
            if value is None or not _satisfies(constraint, value):
                return False
        return True

    def evaluate(
        self,
        capabilities: Sequence[Capability],
        call: NormalizedCall,
        usage: Mapping[str, int],
    ) -> PolicyVerdict:
        spec = self._registry.spec(call.tool)
        if spec is None:
            raise PolicyError(f"unknown tool {call.tool!r}")
        security_params = {n for n, p in spec.params.items() if p.security_relevant}

        for_tool = [c for c in capabilities if c.tool == call.tool]

        # 1. An explicit deny that matches wins over any allow (conflicting rules -> DENY).
        for cap in for_tool:
            if cap.effect == "deny" and self._constraints_hold(cap, call):
                return PolicyVerdict(Verdict.DENY, ReasonCode.EXPLICIT_DENY, cap.cap_id)

        allows = [c for c in for_tool if c.effect == "allow"]
        if not allows:
            return PolicyVerdict(Verdict.DENY, ReasonCode.NO_CAPABILITY)

        # 2. An allow matches only if it constrains every security-relevant argument.
        matching = [
            c
            for c in allows
            if security_params <= set(c.constraints) and self._constraints_hold(c, call)
        ]
        if not matching:
            return PolicyVerdict(Verdict.DENY, ReasonCode.NO_MATCHING_RULE)

        # 3. Call budget: first matching allow that still has budget.
        for cap in matching:
            if cap.max_calls is None or usage.get(cap.cap_id, 0) < cap.max_calls:
                return PolicyVerdict(Verdict.ALLOW, ReasonCode.ALLOWED_BY_POLICY, cap.cap_id)
        return PolicyVerdict(Verdict.DENY, ReasonCode.MAX_CALLS_EXCEEDED, matching[0].cap_id)
