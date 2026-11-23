"""Benign calibration: every user task's ground-truth calls must succeed in B0 and B2.

Run in .venv-bench:  python -I experiments/scripts/m6/replay_user_ground_truth.py
Only user-task ground truth is used here; no injection task is read or executed.
"""

from __future__ import annotations

import json
import sys
import warnings

warnings.filterwarnings("ignore")

from agentguard.benchmarks.agentdojo_banking import (  # noqa: E402
    build_gate,
    build_registry,
    load_suite,
    replay_user_ground_truth,
)
from agentguard.benchmarks.banking_policies import policy_for  # noqa: E402
VERSION = sys.argv[1] if len(sys.argv) > 1 else "banking-v2"
from agentguard.policy.schemas import GatewayMode  # noqa: E402

suite = load_suite()
registry = build_registry(suite)
rows = []
for tid, task in suite.user_tasks.items():
    for mode in (GatewayMode.B0, GatewayMode.B2):
        gate = build_gate(mode, registry)
        res = replay_user_ground_truth(suite, task, gate, policy_for(tid, VERSION))
        gate.gateway.close()
        rows.append(
            {
                "task": tid,
                "mode": mode.value,
                "utility": res.utility,
                "denied": res.denied,
                "calls": [(c.tool, c.verdict, list(c.reasons)) for c in res.calls],
            }
        )
bad = [r for r in rows if not r["utility"] or r["denied"]]
print(json.dumps({"n": len(rows), "failures": bad}, indent=1))
sys.exit(1 if bad else 0)
