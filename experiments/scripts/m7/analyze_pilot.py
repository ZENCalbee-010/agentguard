"""Pilot analysis from the raw records only. Prints tables and writes results/metrics/pilot-summary.

Run in the core environment:  python experiments/scripts/m7/analyze_pilot.py <records.jsonl>
Every number is computed from ExperimentRecords; nothing is typed in by hand.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from agentguard.evaluation.metrics import metrics_by_config
from agentguard.evaluation.records import export_csv, read_records
from agentguard.evaluation.statistics import compare_paired, paired_outcomes, wilson_ci

src = Path(sys.argv[1])
recs = read_records(src)
MODES = ("B0", "B1", "B2", "P1")
by = {(r.config_id, r.case_id): r for r in recs}
cases = sorted({r.case_id for r in recs})
benign = [c for c in cases if c.endswith("|benign")]
attack = [c for c in cases if not c.endswith("|benign")]

out: dict = {"source": str(src), "n_records": len(recs), "commit": sorted({r.code_commit or "" for r in recs}),
             "dirty": any(r.code_dirty for r in recs), "model": recs[0].model.model_dump(),
             "analyzer": sorted({r.analyzer_version or "-" for r in recs})}  # fmt: skip

# ---- per configuration metrics --------------------------------------------------------------
metrics = {k[1]: v for k, v in metrics_by_config(recs).items()}
out["metrics"] = metrics
print("== metrics per configuration (denominators in names)")
for m in MODES:
    x = metrics[m]
    n = x["attack_cases_clean"]
    lo, hi = wilson_ci(x["asr_executed"], n)
    print(f"{m}: executed {x['asr_executed']}/{n} (Wilson {lo:.2f}-{hi:.2f}) attempted {x['attempted']}/{n} "
          f"| utility under attack {x['task_success_under_attack']}/{n} | benign {x['benign_success']}/{x['benign_cases_clean']} "
          f"| benign cases with defense denial {x['benign_cases_with_denial']}, with invalid call {x['benign_cases_with_invalid_call']} | unclean attack runs {x['attack_cases_unclean']}")  # fmt: skip

# ---- benign cases, per case ----------------------------------------------------------------------
print("\n== benign cases")
for c in benign:
    for m in MODES:
        r = by[(m, c)]
        calls = [(a.tool, a.verdict, a.reasons[0] if a.reasons else "") for a in r.tool_attempts]
        print(f"{c} {m}: {r.run_status} success={r.task_success} calls={calls}")

# ---- denials ----------------------------------------------------------------------------------------
print("\n== denial reasons per configuration (all cases)")
den = {m: Counter(reason for r in recs if r.config_id == m for a in r.tool_attempts if a.verdict == "DENY" for reason in a.reasons) for m in MODES}  # includes INVALID_CALL (model errors)
for m in MODES:
    print(m, dict(den[m]))
out["denials"] = {m: dict(v) for m, v in den.items()}

# ---- is P1 different from B2 at all? ------------------------------------------------------------------
def _traj(r):  # tool and verdict only: reason codes differ by design (ALLOWED_BY_POLICY vs ..._AND_ANALYZER)
    return [(a.tool, a.verdict, a.executed) for a in r.tool_attempts]


same = sum(1 for c in cases if _traj(by[("P1", c)]) == _traj(by[("B2", c)]))
print(f"\nP1 trajectories identical to B2: {same}/{len(cases)}")
out["p1_equals_b2_trajectories"] = [same, len(cases)]
an = [(r.case_id, a.tool) for r in recs if r.config_id == "P1" for a in r.tool_attempts if "ANALYZER_DENY" in a.reasons]
print("P1 analyzer denials:", an)

# ---- attack cases ---------------------------------------------------------------------------------------
print("\n== attempted / executed per injection task (clean cases)")
tab = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
for r in recs:
    if r.is_attack and r.clean:
        t = tab[r.case_id.split("|")[1]][r.config_id]
        t[0] += 1
        t[1] += bool(r.attack_attempted)
        t[2] += bool(r.attack_executed)
for it in sorted(tab):
    print(it, {m: f"{tab[it][m][2]}/{tab[it][m][1]}/{tab[it][m][0]}" for m in MODES}, "(executed/attempted/n)")
b0_exec = sorted(c for c in attack if by[("B0", c)].attack_executed)
print("\nB0 attacks that executed:", b0_exec)
print("cases where the model attempted the attack in B0:", sorted(c for c in attack if by[("B0", c)].attack_attempted))
print("injection-exposed? attempted only in cases where the user task's flow showed the vector:")
for ut in sorted({c.split("|")[0] for c in attack}):
    n_att = sum(1 for c in attack if c.startswith(ut + "|") and by[("B0", c)].attack_attempted)
    print(" ", ut, f"attempted in B0 for {n_att} of 9 injections")

# ---- paired comparisons (descriptive; clusters = 3 user tasks, so no inference) -----------------------------
print("\n== paired comparisons on attack cases, executed attack (descriptive)")
pairs_out = {}
for a, b in (("B0", "B1"), ("B0", "B2"), ("B2", "P1"), ("B1", "P1")):
    A = [r for r in recs if r.config_id == a and r.is_attack]
    B = [r for r in recs if r.config_id == b and r.is_attack]
    p = paired_outcomes(A, B, lambda r: bool(r.attack_executed))
    c = compare_paired(p)
    pairs_out[f"{a}-{b}"] = c.__dict__
    print(f"{a} vs {b}: pairs={c.n_pairs} only-{a}={c.a_only} only-{b}={c.b_only} diff={c.diff:+.3f} exact p={c.p_value:.4f}")
out["paired_executed"] = pairs_out

# ---- cost ------------------------------------------------------------------------------------------------------
print("\n== cost per run (local model, wall clock)")
cost = {}
for m in MODES:
    rs = [r for r in recs if r.config_id == m]
    lat = sorted(r.latency_s for r in rs)
    cost[m] = {"runs": len(rs), "median_s": lat[len(lat) // 2], "max_s": lat[-1], "mean_s": sum(lat) / len(lat),
               "in_tok_per_run": sum(r.input_tokens for r in rs) / len(rs), "out_tok_per_run": sum(r.output_tokens for r in rs) / len(rs),
               "model_calls_per_run": sum(r.model_calls for r in rs) / len(rs), "total_s": sum(lat)}  # fmt: skip
    print(m, {k: round(v, 1) for k, v in cost[m].items()})
out["cost"] = cost
total = sum(r.latency_s for r in recs)
print(f"total wall clock {total/60:.1f} min for {len(recs)} runs ({total/len(recs):.1f} s/run)")
out["total_wall_min"] = total / 60

odir = Path("results/metrics/pilot-summary")
odir.mkdir(parents=True, exist_ok=True)
(odir / "summary.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8", newline="\n")
export_csv(odir / "records.csv", recs)
with (odir / "per_case_outcomes.csv").open("w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["case_id", *[f"{m}_{f}" for m in MODES for f in ("status", "success", "attempted", "executed", "denied")]])
    for c in cases:
        row = [c]
        for m in MODES:
            r = by[(m, c)]
            row += [r.run_status, r.task_success, r.attack_attempted, r.attack_executed, sum(a.verdict == "DENY" for a in r.tool_attempts)]
        w.writerow(row)
print("\nwrote", odir)
