"""Static policy-coverage matrix: banking injection ground truth vs frozen user-task policies.

No model is involved. For every (user task, injection task) pair the injection's own
ground-truth calls are executed through the gateway; AgentDojo's security() then reads the
environment. This is the ceiling of what a policy can stop for those exact calls, not an
attack-success rate. B0 is the control: the adapter must not change the native result.

Run in .venv-bench:  python experiments/scripts/m6/policy_coverage_matrix.py [policy-version [out.json]]
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
    replay_injection_ground_truth,
)
from agentguard.benchmarks.banking_policies import policies_hash, policy_for  # noqa: E402
VERSION = sys.argv[1] if len(sys.argv) > 1 else "banking-v2"
from agentguard.policy.schemas import GatewayMode  # noqa: E402

suite = load_suite()
registry = build_registry(suite)
cells = []
for utid, ut in suite.user_tasks.items():
    for itid, it in suite.injection_tasks.items():
        row = {"user_task": utid, "injection_task": itid}
        for mode in (GatewayMode.B0, GatewayMode.B2):
            gate = build_gate(mode, registry)
            res = replay_injection_ground_truth(suite, ut, it, gate, policy_for(utid, VERSION))
            gate.gateway.close()
            row[mode.value] = {
                "security": res.security,
                "denied_calls": res.denied,
                "n_calls": len(res.calls),
                "reasons": sorted({r for c in res.calls for r in c.reasons if c.verdict == "DENY"}),
            }
        cells.append(row)

n = len(cells)
summary = {
    "policy_version": VERSION,
    "policies_hash": policies_hash(VERSION),
    "pairs": n,
    "B0_goal_achieved": sum(1 for c in cells if c["B0"]["security"]),
    "B2_goal_achieved": sum(1 for c in cells if c["B2"]["security"]),
    "by_injection_task": {
        itid: {
            "B0": sum(1 for c in cells if c["injection_task"] == itid and c["B0"]["security"]),
            "B2": sum(1 for c in cells if c["injection_task"] == itid and c["B2"]["security"]),
            "of": len(suite.user_tasks),
        }
        for itid in suite.injection_tasks
    },
    "by_user_task": {
        utid: sum(1 for c in cells if c["user_task"] == utid and c["B2"]["security"])
        for utid in suite.user_tasks
    },
}
out = {"summary": summary, "cells": cells}
if len(sys.argv) > 2:
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
print(json.dumps(summary, indent=1))
