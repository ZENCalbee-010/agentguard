"""Executor: applies a mock tool only for a valid, matching ALLOW decision (SEC-002/003)."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from agentguard.errors import ConfigError, ToolExecutionError, UnauthorizedExecution
from agentguard.policy.schemas import Decision, NormalizedCall, Trust
from agentguard.sandbox.mock_tools import MockToolBackend
from agentguard.sandbox.state import SandboxState, state_diff
from agentguard.storage.audit_logger import AuditLogger


class DecisionVerifier(Protocol):
    def consume(self, decision: Decision, call: NormalizedCall) -> None: ...


class ToolResult(BaseModel):
    """Tool output. Always untrusted data, whatever the tool (SEC-009)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str
    ok: bool
    output: str
    error: str | None = None
    state_changed: bool = False
    source: str
    trust: Trust = Trust.UNTRUSTED


class SandboxExecutor:
    def __init__(
        self,
        state: SandboxState,
        backend: MockToolBackend,
        verifier: DecisionVerifier,
        audit: AuditLogger,
        run_id: str,
    ) -> None:
        if not isinstance(backend, MockToolBackend):
            raise ConfigError("only the simulated MockToolBackend may be executed (SEC-015)")
        state.bind_run(run_id)  # refuses a sandbox that already belongs to another run
        self._state = state
        self._backend = backend
        self._verifier = verifier
        self._audit = audit
        self._run_id = run_id

    def execute(self, call: NormalizedCall, decision: Decision) -> ToolResult:
        try:
            self._verifier.consume(decision, call)
        except UnauthorizedExecution as exc:
            self._audit.append(
                "execution_refused",
                call.task_id,
                {
                    "decision_id": decision.decision_id,
                    "call_hash": call.call_hash,
                    "reason": str(exc),
                },
            )
            raise

        working = self._state.snapshot()
        source = f"tool:{call.tool}"
        try:
            output = self._backend.run(call.tool, working, call.args)
        except ToolExecutionError as exc:
            result = ToolResult(tool=call.tool, ok=False, output="", error=str(exc), source=source)
        except Exception as exc:  # a buggy tool must not leave partial state behind
            result = ToolResult(
                tool=call.tool,
                ok=False,
                output="",
                error=f"internal tool error: {type(exc).__name__}",
                source=source,
            )
        else:
            changed = bool(state_diff(self._state, working))
            self._state.replace_with(working)  # atomic commit
            result = ToolResult(
                tool=call.tool, ok=True, output=output, state_changed=changed, source=source
            )
        self._audit.append(
            "execution",
            call.task_id,
            {
                "decision_id": decision.decision_id,
                "call_hash": call.call_hash,
                "tool": call.tool,
                "ok": result.ok,
                "state_changed": result.state_changed,
                "sandbox_id": self._state.sandbox_id,
                "run_id": self._run_id,
            },
        )
        return result
