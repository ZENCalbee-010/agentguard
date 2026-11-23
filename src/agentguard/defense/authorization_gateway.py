"""Authorization gateway: the single decision point between proposed calls and execution.

Semantics per configuration are specified in docs/spec/architecture.md §4:

* B0 - always ALLOW (call still validated, logged).
* B1 - analyzer decides; error/timeout/malformed verdict -> DENY.
* B2 - capability policy decides (deny-by-default); error -> DENY.
* P1 - policy first and final on DENY (SEC-006); on policy ALLOW the analyzer decides.

A call that fails registry validation is denied in **every** configuration, including B0.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agentguard.agent.tool_registry import ToolRegistry
from agentguard.errors import (
    ConfigError,
    InvalidCallError,
    PermissionChangeRejected,
    UnauthorizedExecution,
)
from agentguard.policy.capability_store import CapabilityStore, TrustedChannel
from agentguard.policy.policy_engine import PolicyEngine, PolicyVerdict
from agentguard.policy.schemas import (
    AnalyzerVerdict,
    Capability,
    ContextItem,
    Decision,
    GatewayMode,
    NormalizedCall,
    Policy,
    ReasonCode,
    ToolCall,
    TrustedTaskContext,
    Verdict,
)
from agentguard.storage.audit_logger import AuditLogger


class ContextAnalyzer(Protocol):
    """Advisory component: it may only turn an ALLOW into a DENY, never the reverse."""

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict: ...


class GatewayConfig(BaseModel):
    """Deliberately tiny: there is no field that can switch enforcement off (SEC-014)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: GatewayMode
    analyzer_timeout_s: float = Field(default=2.0, gt=0, le=60)


@dataclass(frozen=True)
class AuthorizationResult:
    decision: Decision
    call: NormalizedCall | None  # None when the call could not be validated
    # Registry validation message for an invalid call. It is produced before and independently
    # of the configuration, so it says nothing about policy or analyzer.
    invalid_detail: str | None = None


@dataclass
class _TaskRecord:
    ctx: TrustedTaskContext
    store: CapabilityStore
    usage: dict[str, int] = field(default_factory=dict)
    closed: bool = False


class AuthorizationGateway:
    def __init__(
        self,
        config: GatewayConfig,
        registry: ToolRegistry,
        audit: AuditLogger,
        channel: TrustedChannel,
        analyzer: ContextAnalyzer | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        needs_analyzer = config.mode in (GatewayMode.B1, GatewayMode.P1)
        if needs_analyzer and analyzer is None:
            raise ConfigError(f"mode {config.mode} requires a context analyzer")
        if not needs_analyzer and analyzer is not None:
            raise ConfigError(
                f"mode {config.mode} must not be given an analyzer (hidden advantage)"
            )
        self._cfg = config
        self._registry = registry
        self._audit = audit
        self._channel = channel
        self._analyzer = analyzer
        self._engine = policy_engine or PolicyEngine(registry)
        self._mac_key = secrets.token_bytes(32)
        self._tasks: dict[str, _TaskRecord] = {}
        self._consumed: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="analyzer")

    # ---- properties -------------------------------------------------------------------
    @property
    def mode(self) -> GatewayMode:
        return self._cfg.mode

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    # ---- trusted-channel operations --------------------------------------------------
    def _require_channel(self, channel: TrustedChannel) -> None:
        if channel is not self._channel:
            raise PermissionChangeRejected("operation requires the trusted channel")

    def open_task(self, user_prompt: str, policy: Policy, *, channel: TrustedChannel) -> str:
        self._require_channel(channel)
        task_id = uuid.uuid4().hex
        store = CapabilityStore(task_id, policy, self._registry, self._channel.verify)
        ctx = TrustedTaskContext(
            task_id=task_id, user_prompt=user_prompt, policy_hash=store.policy_hash
        )
        self._tasks[task_id] = _TaskRecord(ctx=ctx, store=store)
        self._audit.append(
            "task_open",
            task_id,
            {
                "policy_hash": ctx.policy_hash,
                "mode": self.mode.value,
                "n_capabilities": len(store.capabilities),
            },
        )
        return task_id

    def close_task(self, task_id: str, *, channel: TrustedChannel) -> None:
        self._require_channel(channel)
        rec = self._tasks.get(task_id)
        if rec is not None:
            rec.closed = True
            self._audit.append("task_close", task_id, {})

    def grant(self, task_id: str, capability: Capability, token: str) -> None:
        rec = self._tasks.get(task_id)
        if rec is None or rec.closed:
            raise PermissionChangeRejected("no such active task")
        before = rec.store.policy_hash
        try:
            rec.store.grant(capability, token)
        except PermissionChangeRejected:
            self._audit.append(
                "permission_change",
                task_id,
                {"accepted": False, "cap_id": capability.cap_id, "policy_hash": before},
            )
            raise
        self._audit.append(
            "permission_change",
            task_id,
            {"accepted": True, "cap_id": capability.cap_id, "policy_hash": rec.store.policy_hash},
        )

    def policy_hash(self, task_id: str) -> str:
        return self._tasks[task_id].store.policy_hash

    def task_context(self, task_id: str) -> TrustedTaskContext:
        return self._tasks[task_id].ctx

    # ---- decisions -------------------------------------------------------------------
    def _mac(self, decision_id: str, task_id: str, call_hash: str, verdict: Verdict) -> str:
        msg = f"{decision_id}|{task_id}|{call_hash}|{verdict.value}".encode()
        return hmac.new(self._mac_key, msg, hashlib.sha256).hexdigest()

    def _decide(
        self,
        task_id: str,
        call: NormalizedCall | None,
        verdict: Verdict,
        reasons: tuple[ReasonCode, ...],
        capability_id: str | None = None,
        analyzer: AnalyzerVerdict | None = None,
        detail: dict[str, Any] | None = None,
    ) -> Decision:
        decision_id = uuid.uuid4().hex
        call_hash = call.call_hash if call is not None else "invalid"
        decision = Decision(
            decision_id=decision_id,
            task_id=task_id,
            call_hash=call_hash,
            mode=self.mode,
            verdict=verdict,
            reasons=reasons,
            capability_id=capability_id,
            analyzer=analyzer,
            mac=self._mac(decision_id, task_id, call_hash, verdict),
        )
        rec = self._tasks.get(task_id)
        self._audit.append(
            "decision",
            task_id,
            {
                "decision_id": decision_id,
                "mode": self.mode.value,
                "verdict": verdict.value,
                "reasons": [r.value for r in reasons],
                "capability_id": capability_id,
                "policy_hash": rec.store.policy_hash if rec else None,
                "call": (
                    {
                        "tool": call.tool,
                        "args": call.args,
                        "raw_args": call.raw_args,
                        "hash": call_hash,
                    }
                    if call is not None
                    else None
                ),
                "analyzer": analyzer.model_dump(mode="json") if analyzer else None,
                **(detail or {}),
            },
        )
        return decision

    def _policy_verdict(self, rec: _TaskRecord, call: NormalizedCall) -> PolicyVerdict:
        try:
            return self._engine.evaluate(rec.store.capabilities, call, rec.usage)
        except Exception:  # fail closed on any engine failure (SEC-013)
            return PolicyVerdict(Verdict.DENY, ReasonCode.POLICY_ERROR)

    def _analyzer_verdict(
        self, rec: _TaskRecord, call: NormalizedCall, items: Sequence[ContextItem]
    ) -> tuple[AnalyzerVerdict | None, ReasonCode | None]:
        analyzer = self._analyzer
        if analyzer is None:  # unreachable by construction; fail closed anyway
            return None, ReasonCode.ANALYZER_ERROR
        future = self._pool.submit(analyzer.analyze, rec.ctx.user_prompt, call, tuple(items))
        try:
            verdict = future.result(timeout=self._cfg.analyzer_timeout_s)
        except FutureTimeout:
            future.cancel()
            return None, ReasonCode.ANALYZER_TIMEOUT
        except Exception:
            return None, ReasonCode.ANALYZER_ERROR
        if not isinstance(verdict, AnalyzerVerdict):
            return None, ReasonCode.ANALYZER_ERROR
        return verdict, None

    def authorize(
        self,
        task_id: str,
        proposed: object,
        untrusted: Sequence[ContextItem] = (),
    ) -> AuthorizationResult:
        rec = self._tasks.get(task_id)
        if rec is None or rec.closed:
            return AuthorizationResult(
                self._decide(task_id, None, Verdict.DENY, (ReasonCode.TASK_NOT_ACTIVE,)), None
            )
        try:
            call = self._registry.validate(ToolCall.parse(proposed), task_id)
        except Exception as exc:  # InvalidCallError, but also any unexpected failure: fail closed
            detail = (
                str(exc)
                if isinstance(exc, InvalidCallError)
                else f"unexpected {type(exc).__name__}"
            )
            decision = self._decide(
                task_id,
                None,
                Verdict.DENY,
                (ReasonCode.INVALID_CALL,),
                detail={"invalid_call": detail},
            )
            return AuthorizationResult(decision, None, detail)

        mode = self.mode
        if mode is GatewayMode.B0:
            d = self._decide(task_id, call, Verdict.ALLOW, (ReasonCode.ALLOWED_UNENFORCED,))
            return AuthorizationResult(d, call)

        pv: PolicyVerdict | None = None
        if mode in (GatewayMode.B2, GatewayMode.P1):
            pv = self._policy_verdict(rec, call)
            if pv.verdict is Verdict.DENY:  # policy denial is final (SEC-006)
                d = self._decide(task_id, call, Verdict.DENY, (pv.reason,), pv.capability_id)
                return AuthorizationResult(d, call)
            if mode is GatewayMode.B2:
                if pv.capability_id is not None:
                    rec.usage[pv.capability_id] = rec.usage.get(pv.capability_id, 0) + 1
                d = self._decide(task_id, call, Verdict.ALLOW, (pv.reason,), pv.capability_id)
                return AuthorizationResult(d, call)

        verdict, err = self._analyzer_verdict(rec, call, untrusted)
        cap_id = pv.capability_id if pv else None
        if err is not None:
            d = self._decide(task_id, call, Verdict.DENY, (err,), cap_id)
            return AuthorizationResult(d, call)
        assert verdict is not None  # noqa: S101 - narrowing only; err is None implies a verdict
        if verdict.decision is Verdict.DENY:
            d = self._decide(
                task_id, call, Verdict.DENY, (ReasonCode.ANALYZER_DENY,), cap_id, verdict
            )
            return AuthorizationResult(d, call)
        if pv is not None and pv.capability_id is not None:
            rec.usage[pv.capability_id] = rec.usage.get(pv.capability_id, 0) + 1
        reason = ReasonCode.ALLOWED_BY_POLICY_AND_ANALYZER if pv else ReasonCode.ALLOWED_BY_ANALYZER
        d = self._decide(task_id, call, Verdict.ALLOW, (reason,), cap_id, verdict)
        return AuthorizationResult(d, call)

    # ---- decision verification for the executor --------------------------------------
    def consume(self, decision: Decision, call: NormalizedCall) -> None:
        """Validate a decision for exactly one execution of exactly this call (SEC-002, SEC-007)."""
        expected = self._mac(
            decision.decision_id, decision.task_id, decision.call_hash, decision.verdict
        )
        with self._lock:
            if not hmac.compare_digest(expected, decision.mac):
                raise UnauthorizedExecution("decision was not issued by this gateway")
            if not decision.allowed:
                raise UnauthorizedExecution("decision is not ALLOW")
            if decision.call_hash != call.call_hash or decision.task_id != call.task_id:
                raise UnauthorizedExecution("decision does not match the call or task")
            rec = self._tasks.get(decision.task_id)
            if rec is None or rec.closed:
                raise UnauthorizedExecution("task is not active")
            if decision.decision_id in self._consumed:
                raise UnauthorizedExecution("decision was already used")
            self._consumed.add(decision.decision_id)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
