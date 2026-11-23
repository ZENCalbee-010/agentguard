"""Model qualification on ALL 16 banking user tasks, benign, configuration B0 only.

B0 has no defense, so this cannot be used to tune the defense; it answers only "can the model do
the benign tasks at all" (REQ-AGT-4). Run in .venv-bench:
  python experiments/scripts/m7/qualify_banking_b0.py <out.jsonl> [model] [think: off|none]
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig  # noqa: E402
from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.benchmarks.agentdojo_runner import run_case  # noqa: E402
from agentguard.evaluation.qualification import code_version  # noqa: E402
from agentguard.evaluation.records import read_records, write_records  # noqa: E402
from agentguard.policy.schemas import GatewayMode  # noqa: E402

out = Path(sys.argv[1])
done = {r.case_id for r in read_records(out)} if out.exists() else set()
model = sys.argv[2] if len(sys.argv) > 2 else "qwen3:8b"
think = False if (sys.argv[3] if len(sys.argv) > 3 else "off") == "off" else None
adapter = OllamaAdapter(OllamaConfig(model=model, num_ctx=12288, think=think))
version = code_version(Path.cwd())
suite = ab.load_suite()
registry = ab.build_registry(suite)
for utid in suite.user_tasks:
    if f"{utid}|benign" in done:
        continue
    rec = run_case(adapter, GatewayMode.B0, utid, None, experiment_id="m7-qualification",
                   version=version, suite=suite, registry=registry)  # fmt: skip
    write_records(out, [rec])
    print(utid, rec.run_status, "success", rec.task_success, f"{rec.latency_s:.1f}s", flush=True)
