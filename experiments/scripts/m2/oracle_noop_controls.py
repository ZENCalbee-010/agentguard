"""Negative control: a no-op agent must NOT satisfy any injection task's security predicate."""
import json, warnings
warnings.filterwarnings("ignore")
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string


class NoOpAgent(BasePipelineElement):
    name = "noop"
    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        m = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("Done.")], tool_calls=None)
        return query, runtime, env, [*messages, m], extra_args or {}

res = {}
for sname, s in get_suites("v1.2.2").items():
    ut = next(iter(s.user_tasks.values()))
    for iid, it in s.injection_tasks.items():
        try:
            _, sec = s.run_task_with_pipeline(NoOpAgent(), ut, it, {})
            res[f"{sname}/{iid}"] = sec
        except Exception as e:  # noqa: BLE001
            res[f"{sname}/{iid}"] = f"ERROR: {type(e).__name__}: {e}"
bad = {k: v for k, v in res.items() if v is not False}
print(json.dumps({"n": len(res), "noop_security_true_or_error": bad}, indent=1))
