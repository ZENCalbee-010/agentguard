"""Compare the v1 pilot with the policy-v2 re-pilot from raw records only.

Run in the core environment:
  python experiments/scripts/m7/compare_pilots.py <v1.jsonl> <v2.jsonl>
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from agentguard.benchmarks.banking_analysis import STRATA
from agentguard.evaluation.metrics import metrics_by_config
from agentguard.evaluation.records import read_records
from agentguard.evaluation.statistics import compare_paired, paired_outcomes, wilson_ci

v1 = read_records(Path(sys.argv[1]))
v2 = read_records(Path(sys.argv[2]))
MODES = ("B0", "B1", "B2", "P1")
idx1 = {(r.config_id, r.case_id): r for r in v1}
idx2 = {(r.config_id, r.case_id): r for r in v2}
cases = sorted({r.case_id for r in v2})
out: dict = {"v1": sys.argv[1], "v2": sys.argv[2], "n": [len(v1), len(v2)],
             "commit_v2": sorted({r.code_commit or "" for r in v2}), "dirty_v2": any(r.code_dirty for r in v2),
             "policy_hash_v2": sorted({r.policy_hash for r in v2 if r.config_id == "B2"})}  # fmt: skip


def traj(r):  # tool, verdict, executed (reason codes excluded: they differ by design)
    return [(a.tool, a.verdict, a.executed) for a in r.tool_attempts]


print("== determinism: configurations that do not use the policy must reproduce v1 exactly")
det = {}
for m in ("B0", "B1"):
    same = sum(1 for c in cases if traj(idx1[(m, c)]) == traj(idx2[(m, c)]))
    same_out = sum(1 for c in cases if (idx1[(m, c)].task_success, idx1[(m, c)].attack_executed) == (idx2[(m, c)].task_success, idx2[(m, c)].attack_executed))
    det[m] = {"identical_trajectories": same, "identical_outcomes": same_out, "of": len(cases)}
    print(f"{m}: trajectories identical {same}/{len(cases)}, outcomes identical {same_out}/{len(cases)}")
out["determinism"] = det

print("\n== v2 metrics per configuration (utility shown for each stratum)")
res = {}
for name, excl in STRATA.items():
    mm = {k[1]: v for k, v in metrics_by_config(v2, excl).items()}
    res[name] = mm
m2 = res["all_16"]
for m in MODES:
    x = m2[m]
    n = x["attack_cases_clean"]
    lo, hi = wilson_ci(x["asr_executed"], n)
    util = " ".join(f"{s}: {res[s][m]['task_success_under_attack_valid']}/{res[s][m]['utility_attack_cases_valid']}" for s in STRATA)
    ben = " ".join(f"{s}: {res[s][m]['benign_success_valid']}/{res[s][m]['utility_benign_cases_valid']}" for s in STRATA)
    print(f"{m}: executed {x['asr_executed']}/{n} ({lo:.2f}-{hi:.2f}) attempted {x['attempted']} | util under attack [{util}] | benign [{ben}] "
          f"| benign defense denial {x['benign_cases_with_denial']}/{x['benign_cases_clean']} | unclean attack {x['attack_cases_unclean']}")  # fmt: skip
out["v2_metrics"] = res

print("\n== v1 vs v2 for B2 (the only configuration whose policy changed), per case")
chg = []
for c in cases:
    a, b = idx1[("B2", c)], idx2[("B2", c)]
    if traj(a) != traj(b) or a.task_success != b.task_success or a.attack_executed != b.attack_executed:
        chg.append((c, a.task_success, b.task_success, a.attack_executed, b.attack_executed))
print(f"cases that differ: {len(chg)}/{len(cases)}")
for c, s1, s2, e1, e2 in chg:
    print(f"  {c.split('|')[0]}|{c.split('|')[1]}: success {s1}->{s2}, executed {e1}->{e2}")
out["b2_changed_cases"] = chg
p1_same = sum(1 for c in cases if traj(idx2[("P1", c)]) == traj(idx2[("B2", c)]))
an_den = sum(1 for r in v2 if r.config_id == "P1" for a in r.tool_attempts if "ANALYZER_DENY" in a.reasons)
print(f"\nP1 trajectories identical to B2 (v2): {p1_same}/{len(cases)}; analyzer denials in P1: {an_den}")
out["p1_equals_b2"] = [p1_same, len(cases), an_den]

print("\n== denials (v2), defense decisions only")
den = {m: dict(Counter(x for r in v2 if r.config_id == m for a in r.tool_attempts if a.verdict == "DENY" and a.reasons != ("INVALID_CALL",) for x in a.reasons)) for m in MODES}
inv = {m: sum(1 for r in v2 if r.config_id == m for a in r.tool_attempts if a.reasons == ("INVALID_CALL",)) for m in MODES}
for m in MODES:
    print(m, den[m], "invalid calls:", inv[m])
out["denials_v2"], out["invalid_v2"] = den, inv

print("\n== benign cases (v2)")
for c in [c for c in cases if c.endswith("|benign")]:
    for m in MODES:
        r = idx2[(m, c)]
        print(f"  {c.split('|')[0]} {m}: success={r.task_success} calls={[(a.tool, a.reasons[0] if a.verdict == 'DENY' else 'ok') for a in r.tool_attempts]}")

print("\n== paired executed-attack comparisons (v2, descriptive only: 3 clusters)")
pc = {}
for a, b in (("B0", "B1"), ("B0", "B2"), ("B2", "P1")):
    A = [r for r in v2 if r.config_id == a and r.is_attack]
    B = [r for r in v2 if r.config_id == b and r.is_attack]
    c = compare_paired(paired_outcomes(A, B, lambda r: bool(r.attack_executed)))
    pc[f"{a}-{b}"] = c.__dict__
    print(f"{a} vs {b}: pairs={c.n_pairs} only-{a}={c.a_only} only-{b}={c.b_only} p={c.p_value:.4f}")
out["paired_v2"] = pc

lat = {m: [r.latency_s for r in v2 if r.config_id == m] for m in MODES}
out["cost_v2"] = {m: {"mean_s": sum(v) / len(v), "total_s": sum(v)} for m, v in lat.items()}
tot = sum(sum(v) for v in lat.values())
print(f"\nwall clock v2: {tot/60:.1f} min ({tot/len(v2):.1f} s/run)")
dest = Path("results/metrics/pilot-v2-summary")
dest.mkdir(parents=True, exist_ok=True)
(dest / "summary.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8", newline="\n")
print("wrote", dest)
