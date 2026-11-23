"""AgentDojo banking suite (v1.2.2) behind the AgentGuard gateway.

This module imports ``agentdojo`` and therefore only works inside ``.venv-bench`` (D-010).

Enforcement point: ``GatedToolRunner.run`` is the only place a tool call reaches AgentDojo's
``runtime.run_function``. It asks the gateway for a decision, consumes the (single-use, signed)
decision for exactly that call, and executes the *normalized, typed* arguments, so the value that
was authorized is the value that runs (SEC-011). Denied and invalid calls never reach the
runtime and leave the AgentDojo environment untouched.

Oracles are AgentDojo's own state-based ``utility``/``security`` predicates, evaluated on the
environment; banking has no trace-based oracle (that issue, F-3, concerns Slack only). The three
banking security predicates that are looser than their text (F-4) keep their native semantics.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from agentguard.agent.orchestrator import DENIED_MESSAGE, INVALID_MESSAGE
from agentguard.agent.tool_registry import ParamSpec, ParamType, ToolRegistry, ToolSpec
from agentguard.defense.authorization_gateway import (
    AuthorizationGateway,
    ContextAnalyzer,
    GatewayConfig,
)
from agentguard.errors import ConfigError
from agentguard.policy.capability_store import TrustedChannel
from agentguard.policy.schemas import ContextItem, GatewayMode, Policy, Trust
from agentguard.storage.audit_logger import AuditLogger

BENCHMARK = "agentdojo"
BENCHMARK_VERSION = "v1.2.2"
SUITE = "banking"
T = ParamType

# (type, security_relevant) per parameter, reviewed by hand. Required-ness comes from AgentDojo.
PARAM_TABLE: dict[str, dict[str, tuple[ParamType, bool]]] = {
    "get_iban": {},
    "get_balance": {},
    "get_scheduled_transactions": {},
    "get_user_info": {},
    "get_most_recent_transactions": {"n": (T.INTEGER, False)},
    "read_file": {"file_path": (T.RELPATH, True)},
    "send_money": {
        "recipient": (T.ACCOUNT, True),
        "amount": (T.AMOUNT, True),
        "subject": (T.TEXT, False),
        "date": (T.TEXT, False),
    },
    "schedule_transaction": {
        "recipient": (T.ACCOUNT, True),
        "amount": (T.AMOUNT, True),
        "subject": (T.TEXT, False),
        "date": (T.TEXT, False),
        "recurring": (T.BOOL, False),
    },
    "update_scheduled_transaction": {
        "id": (T.INTEGER, True),
        "recipient": (T.ACCOUNT, True),
        "amount": (T.AMOUNT, True),
        "subject": (T.TEXT, False),
        "date": (T.TEXT, False),
        "recurring": (T.BOOL, False),
    },
    "update_password": {"password": (T.TEXT, True)},
    "update_user_info": {
        "first_name": (T.TEXT, True),
        "last_name": (T.TEXT, True),
        "street": (T.TEXT, True),
        "city": (T.TEXT, True),
    },
}
# Tools that change the environment (reviewed against the tool implementations).
PROTECTED = frozenset(
    {
        "send_money",
        "schedule_transaction",
        "update_scheduled_transaction",
        "update_password",
        "update_user_info",
    }
)


def load_suite() -> Any:
    return get_suites(BENCHMARK_VERSION)[SUITE]


def build_registry(suite: Any | None = None) -> ToolRegistry:
    """Registry from AgentDojo's own tool schemas; refuses to build if the reviewed table
    does not match the installed AgentDojo exactly (guards against version drift)."""
    suite = suite or load_suite()
    actual = {t.name: t for t in suite.tools}
    if set(actual) != set(PARAM_TABLE):
        raise ConfigError(f"banking tools changed: {sorted(set(actual) ^ set(PARAM_TABLE))}")
    specs = []
    for name, tool in sorted(actual.items()):
        fields = tool.parameters.model_fields
        if set(fields) != set(PARAM_TABLE[name]):
            raise ConfigError(f"parameters of {name} changed: {sorted(fields)}")
        params = {
            p: ParamSpec(type=ptype, security_relevant=sec, required=fields[p].is_required())
            for p, (ptype, sec) in PARAM_TABLE[name].items()
        }
        specs.append(
            ToolSpec(
                name=name,
                description=(tool.description or "").strip().split("\n")[0][:300],
                params=params,
                protected=name in PROTECTED,
            )
        )
    return ToolRegistry(specs)


def _typed(registry: ToolRegistry, tool: str, args: Mapping[str, str]) -> dict[str, Any]:
    """Normalized string arguments -> the Python types AgentDojo's function expects."""
    spec = registry.spec(tool)
    assert spec is not None  # noqa: S101 - the call was validated against this registry
    out: dict[str, Any] = {}
    for name, value in args.items():
        ptype = spec.params[name].type
        if ptype is T.INTEGER:
            out[name] = int(value)
        elif ptype is T.BOOL:
            out[name] = value == "true"
        elif ptype is T.AMOUNT:
            out[name] = float(Decimal(value))
        else:
            out[name] = value
    return out


@dataclass(frozen=True)
class GatedCall:
    tool: str
    raw_args: Any
    verdict: str
    reasons: tuple[str, ...]
    executed: bool
    error: str | None
    normalized_args: dict[str, str] | None


@dataclass
class GatedToolRunner:
    gateway: AuthorizationGateway
    audit: AuditLogger
    registry: ToolRegistry
    task_id: str
    context: list[ContextItem] = field(default_factory=list)
    calls: list[GatedCall] = field(default_factory=list)

    def run(
        self, runtime: FunctionsRuntime, env: Env, function: str, args: Mapping[str, Any]
    ) -> tuple[str, str | None]:
        """Returns (text shown to the model, error). Never raises for denied/invalid calls."""
        res = self.gateway.authorize(
            self.task_id, {"tool": function, "args": dict(args)}, self.context
        )
        d = res.decision
        reasons = tuple(r.value for r in d.reasons)
        if res.call is None:
            self._note(function, args, d.verdict.value, reasons, False, None, None)
            # AgentDojo's native executor also tells the model what was wrong (D-015).
            return f"Tool call rejected: {res.invalid_detail or 'invalid call'}", None
        if not d.allowed:
            self._note(function, args, d.verdict.value, reasons, False, None, res.call.args)
            return DENIED_MESSAGE, None
        self.gateway.consume(d, res.call)  # signed, single-use, bound to this exact call
        result, error = runtime.run_function(
            env, function, _typed(self.registry, function, res.call.args)
        )
        text = tool_result_to_str(result) if error is None else f"Error: {error}"
        self.context.append(
            ContextItem(text=text, source=f"tool:{function}", trust=Trust.UNTRUSTED)
        )
        self.audit.append(
            "execution",
            self.task_id,
            {"decision_id": d.decision_id, "call_hash": res.call.call_hash, "tool": function,
             "ok": error is None},
        )  # fmt: skip
        self._note(function, args, d.verdict.value, reasons, True, error, res.call.args)
        return text, error

    def _note(self, fn: str, raw: Any, verdict: str, reasons: tuple[str, ...], executed: bool,
              error: str | None, normalized: dict[str, str] | None) -> None:  # fmt: skip
        self.calls.append(GatedCall(fn, raw, verdict, reasons, executed, error, normalized))


class GatedToolsExecutor(BasePipelineElement):  # type: ignore[misc]
    """Drop-in replacement for AgentDojo's ToolsExecutor that goes through the gateway."""

    def __init__(self, runner: GatedToolRunner) -> None:
        self.runner = runner

    def query(  # type: ignore[no-untyped-def]
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),  # noqa: B008 - signature fixed by BasePipelineElement
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},  # noqa: B006 - signature fixed by BasePipelineElement
    ):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = []
        for call in messages[-1]["tool_calls"]:
            if call.function == EMPTY_FUNCTION_NAME:
                text, error = INVALID_MESSAGE, None
            else:
                text, error = self.runner.run(runtime, env, call.function, call.args)
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(text)],
                    tool_call_id=call.id,
                    tool_call=call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args


@dataclass
class Gate:
    """Everything needed to run one task under one configuration."""

    gateway: AuthorizationGateway
    audit: AuditLogger
    registry: ToolRegistry
    channel: TrustedChannel

    def runner(self, user_prompt: str, policy: Policy) -> GatedToolRunner:
        task_id = self.gateway.open_task(user_prompt, policy, channel=self.channel)
        return GatedToolRunner(self.gateway, self.audit, self.registry, task_id)


def build_gate(
    mode: GatewayMode,
    registry: ToolRegistry | None = None,
    analyzer: ContextAnalyzer | None = None,
) -> Gate:
    registry = registry or build_registry()
    audit, channel = AuditLogger(), TrustedChannel()
    gateway = AuthorizationGateway(
        GatewayConfig(mode=mode), registry, audit, channel, analyzer=analyzer
    )
    return Gate(gateway, audit, registry, channel)


@dataclass(frozen=True)
class ReplayResult:
    utility: bool | None  # user-task utility (None for injection replays)
    security: bool | None  # injection achieved (None for user-task replays)
    calls: tuple[GatedCall, ...]

    @property
    def denied(self) -> int:
        return sum(1 for c in self.calls if c.verdict == "DENY")


def _fresh_env(suite: Any, user_task: Any) -> tuple[Any, Any]:
    env = user_task.init_environment(suite.load_and_inject_default_environment({}))
    return env, env.model_copy(deep=True)


def replay_user_ground_truth(
    suite: Any, user_task: Any, gate: Gate, policy: Policy
) -> ReplayResult:
    """Run the user task's ground-truth calls through the gate; score with AgentDojo's utility."""
    env, pre = _fresh_env(suite, user_task)
    runtime = FunctionsRuntime(suite.tools)
    runner = gate.runner(user_task.PROMPT, policy)
    gt = user_task.ground_truth(env)
    for call in gt:
        runner.run(runtime, env, call.function, call.args)
    out = [text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]
    utility = suite._check_task_result(user_task, out, pre, env, gt)
    return ReplayResult(bool(utility), None, tuple(runner.calls))


def replay_injection_ground_truth(
    suite: Any, user_task: Any, injection_task: Any, gate: Gate, policy: Policy
) -> ReplayResult:
    """Static coverage probe: what the *injection's own* calls would do under this gate and policy.
    No model is involved; the result is read from the environment by AgentDojo's security()."""
    env, pre = _fresh_env(suite, user_task)
    runtime = FunctionsRuntime(suite.tools)
    runner = gate.runner(user_task.PROMPT, policy)
    gt = injection_task.ground_truth(env.model_copy(deep=True))
    for call in gt:
        runner.run(runtime, env, call.function, call.args)
    out = [text_content_block_from_string("")]
    security = suite._check_task_result(injection_task, out, pre, env, gt)
    return ReplayResult(None, bool(security), tuple(runner.calls))


def injectable_vectors(suite: Any, user_task: Any) -> frozenset[str]:
    """Injection vectors whose canary text reaches the agent during the user task's ground truth.

    Replaces AgentDojo's own `check()` injectability test, which is broken in 0.1.35 (F-1).
    """
    vectors = suite.get_injection_vector_defaults()
    canary = {v: f"CANARY_{v}" for v in vectors}
    base = suite.load_and_inject_default_environment(canary)
    env = user_task.init_environment(base.model_copy(deep=True))
    runtime = FunctionsRuntime(suite.tools)
    seen: set[str] = set()
    for call in user_task.ground_truth(env.model_copy(deep=True)):
        out, _ = runtime.run_function(env, call.function, call.args)
        seen |= {v for v in vectors if canary[v] in str(out)}
    return frozenset(seen)
