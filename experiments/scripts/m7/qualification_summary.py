"""Compare model qualification on banking benign tasks (B0) across the pinned utility strata.

Run in the core environment:
  python experiments/scripts/m7/qualification_summary.py results/raw/m7-qualification/*.jsonl
Every number is computed from the records.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from agentguard.benchmarks.banking_analysis import STRATA
from agentguard.evaluation.records import read_records
from agentguard.evaluation.statistics import wilson_ci

out: dict[str, dict] = {}
for path in sys.argv[1:]:
    recs = read_records(Path(path))
    model = recs[0].model.model_id
    clean = [r for r in recs if r.clean]
    row: dict = {
        "file": path, "model": model, "digest": recs[0].model.digest, "params": recs[0].model.params,
        "commit": sorted({r.code_commit or "" for r in recs}), "dirty": any(r.code_dirty for r in recs),
        "records": len(recs), "unclean": len(recs) - len(clean),
    }  # fmt: skip
    for name, excluded in STRATA.items():
        used = [r for r in clean if r.task_id not in excluded]
        k = sum(1 for r in used if r.task_success)
        lo, hi = wilson_ci(k, len(used))
        row[name] = {"success": k, "n": len(used), "wilson95": [round(lo, 2), round(hi, 2)]}
    calls = [a for r in recs for a in r.tool_attempts]
    row["tool_calls"] = len(calls)
    row["invalid_call_rate"] = round(sum(1 for a in calls if a.reasons == ("INVALID_CALL",)) / max(1, len(calls)), 3)
    row["runs_with_no_tool_call"] = sum(1 for r in recs if not r.tool_attempts)
    row["successes"] = sorted(r.task_id for r in recs if r.task_success)
    row["median_latency_s"] = sorted(r.latency_s for r in recs)[len(recs) // 2]
    out[model] = row
    print(f"{model}: " + " | ".join(f"{n} {row[n]['success']}/{row[n]['n']} {row[n]['wilson95']}" for n in STRATA))
    print(f"   invalid-call rate {row['invalid_call_rate']} ({row['tool_calls']} calls), runs with no tool call {row['runs_with_no_tool_call']}/{len(recs)}, "
          f"successes {row['successes']}, unclean {row['unclean']}, median {row['median_latency_s']:.1f}s")  # fmt: skip
    print("   tools used:", dict(Counter(a.tool for a in calls)))

dest = Path("results/metrics/qualification-summary")
dest.mkdir(parents=True, exist_ok=True)
(dest / "banking_b0_benign.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
print("wrote", dest)
