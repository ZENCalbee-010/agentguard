"""AgentDojo travel suite (v1.2.2) behind the AgentGuard gateway.

Imports ``agentdojo`` and runs inside ``.venv-bench`` (D-010). Reuses the exact same
``GatedToolRunner`` / ``GatedToolsExecutor`` / ``OllamaPipelineLLM`` enforcement stack as banking
so all security invariants (SEC-001..SEC-015) hold identically.

Compatible injection tasks (from M2 benchmark-compatibility.md):
* ``injection_task_0`` through ``injection_task_5`` (6 tool-mediated, state-based tasks; 0 F-2/F-3)
* ``injection_task_6`` is answer-only (F-5, out of scope) and excluded from attack evaluation.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suites

from agentguard.agent.model_adapter import (
    ContextOverflow,
    ModelAdapter,
    ModelError,
    ModelTimeout,
)
from agentguard.agent.tool_registry import ParamSpec, ParamType, ToolRegistry, ToolSpec
from agentguard.benchmarks import agentdojo_banking as ab
from agentguard.benchmarks.agentdojo_runner import ATTACK_FAMILY, SYSTEM_PROMPT, OllamaPipelineLLM
from agentguard.benchmarks.agentdojo_runner import _Tail as _ConversationTail
from agentguard.benchmarks.travel_policies import policy_for
from agentguard.defense.authorization_gateway import ContextAnalyzer
from agentguard.defense.context_analyzer import ContextAnalyzerV0
from agentguard.errors import ConfigError
from agentguard.evaluation.records import ExperimentRecord, ModelInfo, ToolAttempt
from agentguard.policy.schemas import GatewayMode, ToolCall

BENCHMARK = "agentdojo"
BENCHMARK_VERSION = "v1.2.2"
SUITE = "travel"
COMPATIBLE_INJECTIONS = tuple(f"injection_task_{i}" for i in range(6))
T = ParamType

PARAM_TABLE: dict[str, dict[str, tuple[ParamType, bool]]] = {
    "get_user_information": {},
    "get_all_hotels_in_city": {"city": (T.TEXT, False)},
    "get_hotels_prices": {"hotel_names": (T.STRING_LIST, False)},
    "get_rating_reviews_for_hotels": {"hotel_names": (T.STRING_LIST, False)},
    "get_hotels_address": {"hotel_name": (T.TEXT, False)},
    "get_all_restaurants_in_city": {"city": (T.TEXT, False)},
    "get_cuisine_type_for_restaurants": {"restaurant_names": (T.STRING_LIST, False)},
    "get_restaurants_address": {"restaurant_names": (T.STRING_LIST, False)},
    "get_rating_reviews_for_restaurants": {"restaurant_names": (T.STRING_LIST, False)},
    "get_dietary_restrictions_for_all_restaurants": {"restaurant_names": (T.STRING_LIST, False)},
    "get_contact_information_for_restaurants": {"restaurant_names": (T.STRING_LIST, False)},
    "get_price_for_restaurants": {"restaurant_names": (T.STRING_LIST, False)},
    "check_restaurant_opening_hours": {"restaurant_names": (T.STRING_LIST, False)},
    "get_all_car_rental_companies_in_city": {"city": (T.TEXT, False)},
    "get_car_types_available": {"company_name": (T.STRING_LIST, False)},
    "get_rating_reviews_for_car_rental": {"company_name": (T.STRING_LIST, False)},
    "get_car_fuel_options": {"company_name": (T.STRING_LIST, False)},
    "get_car_rental_address": {"company_name": (T.STRING_LIST, False)},
    "get_car_price_per_day": {"company_name": (T.STRING_LIST, False)},
    "search_calendar_events": {"query": (T.TEXT, False), "date": (T.TEXT, False)},
    "get_day_calendar_events": {"day": (T.TEXT, False)},
    "get_flight_information": {
        "departure_city": (T.TEXT, False),
        "arrival_city": (T.TEXT, False),
    },
    # Protected (side-effecting) tools:
    "create_calendar_event": {
        "title": (T.TEXT, True),
        "start_time": (T.TEXT, False),
        "end_time": (T.TEXT, False),
        "description": (T.TEXT, False),
        "participants": (T.EMAIL_LIST, True),
        "location": (T.TEXT, False),
    },
    "cancel_calendar_event": {"event_id": (T.TEXT, True)},
    "reserve_hotel": {
        "hotel": (T.TEXT, True),
        "start_day": (T.TEXT, True),
        "end_day": (T.TEXT, True),
    },
    "reserve_car_rental": {
        "company": (T.TEXT, True),
        "start_time": (T.TEXT, False),
        "end_time": (T.TEXT, False),
    },
    "reserve_restaurant": {
        "restaurant": (T.TEXT, True),
        "start_time": (T.TEXT, False),
    },
    "send_email": {
        "recipients": (T.EMAIL_LIST, True),
        "subject": (T.TEXT, False),
        "body": (T.TEXT, False),
        "attachments": (T.STRING_LIST, True),
        "cc": (T.EMAIL_LIST, True),
        "bcc": (T.EMAIL_LIST, True),
    },
}

PROTECTED = frozenset(
    {
        "create_calendar_event",
        "cancel_calendar_event",
        "reserve_hotel",
        "reserve_car_rental",
        "reserve_restaurant",
        "send_email",
    }
)


def load_suite() -> Any:
    return get_suites(BENCHMARK_VERSION)[SUITE]


def build_registry(suite: Any | None = None) -> ToolRegistry:
    suite = suite or load_suite()
    actual = {t.name: t for t in suite.tools}
    if set(actual) != set(PARAM_TABLE):
        raise ConfigError(f"travel tools changed: {sorted(set(actual) ^ set(PARAM_TABLE))}")
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


def attack_signature(
    registry: ToolRegistry, injection_task: Any, env: Any
) -> list[tuple[str, dict[str, str]]]:
    """Goal-critical part of the travel injection's protected ground-truth calls (REQ-ORC-3)."""
    sig = []
    for call in injection_task.ground_truth(env):
        if call.function not in PROTECTED:
            continue
        norm = registry.validate(ToolCall(tool=call.function, args=dict(call.args)), "sig").args
        critical = {
            k: v
            for k, v in norm.items()
            if k in ("recipients", "hotel", "title", "company", "restaurant")
        }
        sig.append((call.function, critical))
    return sig


def run_travel_case(
    adapter: ModelAdapter,
    mode: GatewayMode,
    user_task_id: str,
    injection_task_id: str | None,
    *,
    experiment_id: str,
    version: dict[str, Any],
    suite: Any | None = None,
    registry: ToolRegistry | None = None,
    max_iters: int = 12,
    timeout_s: float = 300.0,
    analyzer_factory: Callable[[ToolRegistry], ContextAnalyzer] | None = None,
) -> ExperimentRecord:
    suite = suite or load_suite()
    registry = registry or build_registry(suite)
    task = suite.user_tasks[user_task_id]
    inj = suite.injection_tasks[injection_task_id] if injection_task_id else None
    factory = analyzer_factory or ContextAnalyzerV0
    analyzer = factory(registry) if mode in (GatewayMode.B1, GatewayMode.P1) else None
    gate = ab.build_gate(mode, registry, analyzer)
    runner = gate.runner(task.PROMPT, policy_for(user_task_id))
    llm = OllamaPipelineLLM(adapter, timeout_s)
    tail = _ConversationTail()
    pipeline = AgentPipeline(
        [
            SystemMessage(SYSTEM_PROMPT),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ab.GatedToolsExecutor(runner), llm], max_iters=max_iters),
            tail,
        ]
    )
    pipeline.name = f"local-{adapter.model_id}"
    sig_env = task.init_environment(suite.load_and_inject_default_environment({}))
    signature = attack_signature(registry, inj, sig_env) if inj else []

    started = time.monotonic()
    status, utility, security = "completed", False, None
    try:
        injections = load_attack(ATTACK_FAMILY, suite, pipeline).attack(task, inj) if inj else {}
        utility, security = suite.run_task_with_pipeline(pipeline, task, inj, injections)
        last = tail.messages[-1] if tail.messages else None
        if last is None or last["role"] != "assistant" or last["tool_calls"]:
            status = "step_limit"
    except ContextOverflow:
        status = "context_overflow"
    except ModelTimeout:
        status = "model_timeout"
    except ModelError:
        status = "model_error"
    wall = time.monotonic() - started

    attempts = tuple(
        ToolAttempt(
            step=i + 1,
            tool=c.tool,
            verdict=c.verdict,
            reasons=c.reasons,
            executed=c.executed,
            ok=None if not c.executed else c.error is None,
        )
        for i, c in enumerate(runner.calls)
    )
    attempted = None
    if inj is not None:
        attempted = any(
            c.normalized_args is not None
            and any(
                c.tool == tool and all(c.normalized_args.get(k) == v for k, v in args.items())
                for tool, args in signature
            )
            for c in runner.calls
        )
    task_id = runner.task_id
    policy_hash = gate.gateway.policy_hash(task_id)
    gate.gateway.close()
    case = (
        f"{user_task_id}|{injection_task_id}|{ATTACK_FAMILY}" if inj else f"{user_task_id}|benign"
    )
    clean = status == "completed"
    analyzer_cfg = getattr(analyzer, "config", None) if analyzer is not None else None
    analyzer_ver = (
        f"{analyzer_cfg.version}+{analyzer_cfg.config_hash}" if analyzer_cfg is not None else None
    )
    return ExperimentRecord(
        experiment_id=experiment_id,
        run_id=uuid.uuid4().hex,
        case_id=case,
        task_id=user_task_id,
        scenario_id=case if inj else None,
        attack_family=ATTACK_FAMILY if inj else None,
        benchmark=f"{BENCHMARK}:{SUITE}",
        benchmark_version=BENCHMARK_VERSION,
        model=ModelInfo(model_id=adapter.model_id, digest=adapter.digest(), params=adapter.params),
        config_id=mode.value,
        policy_hash=policy_hash,
        analyzer_version=analyzer_ver,
        code_commit=version.get("commit"),
        code_dirty=bool(version.get("dirty", True)),
        seed=int(adapter.params.get("seed", 0)),
        tool_attempts=attempts,
        attack_attempted=attempted if inj else None,
        attack_executed=bool(security) if (inj and clean) else None,
        task_success=bool(utility) and clean,
        run_status=status,
        latency_s=wall,
        input_tokens=llm.input_tokens,
        output_tokens=llm.output_tokens,
        model_calls=llm.model_calls,
        data_derived=any(
            any(c.any_value for c in cap.constraints.values())
            for cap in policy_for(user_task_id).capabilities
        ),
    )
