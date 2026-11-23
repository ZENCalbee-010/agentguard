"""M2 smoke test (no LLM): AgentDojo native checks + oracle semantics probes."""
import json
import warnings

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

warnings.filterwarnings("ignore")
VER = "v1.2.2"
suites = get_suites(VER)
out: dict = {"benchmark_version": VER, "suites": {}}

# 1. native suite.check() -- validates ground truths against utility/security
for name, s in suites.items():
    ok, (user_res, inj_res) = s.check(check_injectable=True)
    out["suites"][name] = {
        "check_ok": ok,
        "user_tasks": len(s.user_tasks),
        "injection_tasks": len(s.injection_tasks),
        "user_tasks_failing_ground_truth": [k for k, (u, msg) in user_res.items() if not u],
        "injection_tasks_failing_ground_truth": [k for k, v in inj_res.items() if not v],
    }

# 2. ground-truth pipeline end-to-end on one banking pair
s = suites["banking"]
ut, it = s.user_tasks["user_task_0"], s.injection_tasks["injection_task_0"]
u_ok, _ = s.run_task_with_pipeline(GroundTruthPipeline(ut), ut, None, {})
_, sec_gt_injection = s.run_task_with_pipeline(GroundTruthPipeline(it), ut, it, {})
out["banking_gt_user_task_0_utility"] = u_ok
out["banking_gt_injection_0_security_when_ground_truth_executed"] = sec_gt_injection
# negative control: agent that does nothing -> security must be False
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string


class NoOpAgent(BasePipelineElement):
    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("I did nothing.")], tool_calls=None)
        return query, runtime, env, [*messages, msg], extra_args or {}


_, sec_noop = s.run_task_with_pipeline(NoOpAgent(), ut, it, {})
out["banking_noop_agent_security"] = sec_noop

# 3. probe InjectionTask0.security() operator-precedence behaviour
env = s.load_and_inject_default_environment({})
pre = env.model_copy(deep=True)
post = env.model_copy(deep=True)
from agentdojo.default_suites.v1.tools.banking_client import Transaction  # noqa: E402

svc = it.get_streaming_service(pre)
post.bank_account.transactions.append(
    Transaction(id=999, sender="x", recipient=it._ATTACKER_IBAN, amount=0.01,
                subject="UNRELATED TEXT NOT MENTIONING ANY SERVICE", date="2022-01-01", recurring=False)
)
out["probe_injection0_service_in_history"] = svc
out["probe_injection0_security_with_unrelated_subject"] = it.security("", pre, post)
post2 = env.model_copy(deep=True)
out["probe_injection0_security_no_attacker_tx"] = it.security("", pre, post2)

# 4. slack: trace-based security and utility
sl = suites["slack"]
out["slack_injection_tasks_trace_based"] = [
    k for k, t in sl.injection_tasks.items()
    if type(t).security_from_traces is not type(t).__mro__[-2].__dict__.get("security_from_traces", None)
    and "security_from_traces" in type(t).__dict__
]
out["slack_user_tasks_trace_based"] = [
    k for k, t in sl.user_tasks.items() if "utility_from_traces" in type(t).__dict__
]
print(json.dumps(out, indent=2))
