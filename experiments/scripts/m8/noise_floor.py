"""Run-to-run agreement of two runs of configuration B0 on the same cases (M8b, descriptive).

  python experiments/scripts/m8/noise_floor.py <main.jsonl> <repeat.jsonl> <out.json>

Compares the latest attempt per case of the B0 arm of the main run with the repeat run: agreement of
the run status, the attempt, the executed unauthorized action, task success and the tool trajectory
(tool, verdict, executed). Disagreements are counted, never explained away; nothing is pooled.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentguard.evaluation.records import ExperimentRecord, read_records
from agentguard.evaluation.run_control import latest_per_case
from agentguard.evaluation.statistics import exact_binomial_ci

main_path, repeat_path, out_path = (Path(a) for a in sys.argv[1:4])
first = {k: v for k, v in latest_per_case(read_records(main_path)).items() if k[0] == "B0"}
second = {k: v for k, v in latest_per_case(read_records(repeat_path)).items() if k[0] == "B0"}
keys = sorted(set(first) & set(second))


def trajectory(r: ExperimentRecord) -> list[tuple[str, str, bool]]:
    return [(a.tool, a.verdict, a.executed) for a in r.tool_attempts]


fields = {
    "run_status": lambda r: r.run_status,
    "attack_attempted": lambda r: r.attack_attempted,
    "attack_executed": lambda r: r.attack_executed,
    "task_success": lambda r: r.task_success,
    "trajectory": trajectory,
}
report: dict[str, object] = {"cases_compared": len(keys), "only_in_main": len(set(first) - set(second)), "only_in_repeat": len(set(second) - set(first))}
for name, get in fields.items():
    diff = [k[1] for k in keys if get(first[k]) != get(second[k])]
    lo, hi = exact_binomial_ci(len(diff), len(keys)) if keys else (None, None)
    report[name] = {"disagreeing_cases": len(diff), "of": len(keys), "exact_ci95": [lo, hi], "cases": diff}
    print(f"{name}: {len(diff)}/{len(keys)} cases differ between the two runs (exact 95% CI {lo}, {hi})")
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
print("wrote", out_path)
