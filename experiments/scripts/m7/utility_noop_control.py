"""Negative control for the utility oracles: does a do-nothing agent pass any banking user task?

Run in .venv-bench: python experiments/scripts/m7/utility_noop_control.py
"""

from __future__ import annotations

import json
import warnings

warnings.filterwarnings("ignore")

from agentdojo.types import text_content_block_from_string  # noqa: E402

from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402

suite = ab.load_suite()
rows = {}
for tid, task in suite.user_tasks.items():
    env = task.init_environment(suite.load_and_inject_default_environment({}))
    pre = env.model_copy(deep=True)
    # no tool calls, unchanged environment, a final answer that carries no information
    out = [text_content_block_from_string("I could not do that.")]
    rows[tid] = bool(suite._check_task_result(task, out, pre, env.model_copy(deep=True), []))
print(json.dumps({"noop_passes": sorted(t for t, v in rows.items() if v), "n": len(rows)}, indent=1))
