"""Composition root: one shared construction path for all four configurations.

Using a single builder for B0/B1/B2/P1 is what guarantees that configurations differ only in
``GatewayMode`` (REQ-EVL-1, SEC-014).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from agentguard.agent.tool_registry import ToolRegistry, default_registry
from agentguard.defense.authorization_gateway import (
    AuthorizationGateway,
    ContextAnalyzer,
    GatewayConfig,
)
from agentguard.policy.capability_store import TrustedChannel
from agentguard.policy.policy_engine import PolicyEngine
from agentguard.policy.schemas import ContextItem, Decision, GatewayMode, NormalizedCall, Policy
from agentguard.sandbox.executor import SandboxExecutor, ToolResult
from agentguard.sandbox.mock_tools import MockToolBackend
from agentguard.sandbox.state import SandboxState
from agentguard.storage.audit_logger import AuditLogger


@dataclass(frozen=True)
class StepOutcome:
    decision: Decision
    result: ToolResult | None  # None when nothing was executed
    call: NormalizedCall | None = None  # the validated, normalized call (None if invalid)


@dataclass
class Stack:
    gateway: AuthorizationGateway
    executor: SandboxExecutor
    audit: AuditLogger
    state: SandboxState
    registry: ToolRegistry
    channel: TrustedChannel  # held by the runner only; never handed to the agent loop

    def open_task(self, user_prompt: str, policy: Policy) -> str:
        return self.gateway.open_task(user_prompt, policy, channel=self.channel)

    def close_task(self, task_id: str) -> None:
        self.gateway.close_task(task_id, channel=self.channel)

    def step(
        self, task_id: str, proposed: object, untrusted: Sequence[ContextItem] = ()
    ) -> StepOutcome:
        """authorize -> (execute iff ALLOW). The only path from a proposed call to a side effect."""
        res = self.gateway.authorize(task_id, proposed, untrusted)
        if res.call is None or not res.decision.allowed:
            return StepOutcome(res.decision, None, res.call)
        return StepOutcome(res.decision, self.executor.execute(res.call, res.decision), res.call)


def build_stack(
    mode: GatewayMode,
    *,
    analyzer: ContextAnalyzer | None = None,
    state: SandboxState | None = None,
    backend: MockToolBackend | None = None,
    registry: ToolRegistry | None = None,
    policy_engine: PolicyEngine | None = None,
    audit: AuditLogger | None = None,
    analyzer_timeout_s: float = 2.0,
    run_id: str | None = None,
) -> Stack:
    registry = registry or default_registry()
    audit = audit or AuditLogger()
    state = state or SandboxState()
    channel = TrustedChannel()
    gateway = AuthorizationGateway(
        GatewayConfig(mode=mode, analyzer_timeout_s=analyzer_timeout_s),
        registry,
        audit,
        channel,
        analyzer=analyzer,
        policy_engine=policy_engine,
    )
    executor = SandboxExecutor(
        state, backend or MockToolBackend(), gateway, audit, run_id or uuid.uuid4().hex
    )
    return Stack(gateway, executor, audit, state, registry, channel)
