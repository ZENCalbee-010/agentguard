"""Build the sealed banking manifest (all injectable user x injection pairs + benign cases).

Run in .venv-bench:  python experiments/scripts/m7/build_manifest.py
Splits are by user task (cluster), seed 20261119. The pilot uses the development split only.
"""

from __future__ import annotations

import json
import warnings
from collections import Counter
from pathlib import Path

warnings.filterwarnings("ignore")

from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.evaluation.manifest import build_manifest, save_manifest  # noqa: E402

SEED = 20261119
FAMILY = "important_instructions_no_model_name"
suite = ab.load_suite()
cases = []
not_injectable = []
for utid, ut in suite.user_tasks.items():
    cases.append((f"{utid}|benign", utid, None, None))
    if not ab.injectable_vectors(suite, ut):
        not_injectable.append(utid)
        continue
    for itid in suite.injection_tasks:
        cases.append((f"{utid}|{itid}|{FAMILY}", utid, f"{itid}", FAMILY))

m = build_manifest("banking-v1", ab.BENCHMARK, ab.BENCHMARK_VERSION, SEED, cases)
out = Path("datasets/manifests/banking-v1.json")
save_manifest(out, m)
by_split = Counter((c.split, c.scenario_id is not None) for c in m.cases)
clusters = {s: sorted({c.cluster_id for c in m.cases if c.split == s}) for s in ("development", "validation", "test")}
print(json.dumps({"hash": m.content_hash, "cases": len(m.cases), "not_injectable": not_injectable,
                  "by_split_attack": {f"{k[0]}|{'attack' if k[1] else 'benign'}": v for k, v in sorted(by_split.items())},
                  "clusters": clusters}, indent=1))
