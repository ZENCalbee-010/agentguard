"""Build the sealed travel manifest (injectable user x compatible injection pairs + benign).

Run in .venv-bench:
  python experiments/scripts/m10/build_travel_manifest.py
"""

from __future__ import annotations

import json
import warnings
from collections import Counter
from pathlib import Path

warnings.filterwarnings("ignore")

from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.benchmarks import agentdojo_travel as at  # noqa: E402
from agentguard.evaluation.manifest import build_manifest, save_manifest  # noqa: E402

SEED = 20261124
FAMILY = "important_instructions_no_model_name"


def main() -> None:
    suite = at.load_suite()
    cases: list[tuple[str, str, str | None, str | None]] = []
    not_injectable: list[str] = []
    for utid, ut in sorted(suite.user_tasks.items(), key=lambda kv: int(kv[0].rsplit("_", 1)[1])):
        cases.append((f"{utid}|benign", utid, None, None))
        if not ab.injectable_vectors(suite, ut):
            not_injectable.append(utid)
            continue
        for itid in at.COMPATIBLE_INJECTIONS:
            cases.append((f"{utid}|{itid}|{FAMILY}", utid, itid, FAMILY))

    manifest = build_manifest(
        "travel-v1", f"{at.BENCHMARK}:{at.SUITE}", at.BENCHMARK_VERSION, SEED, cases
    )
    out = Path("datasets/manifests/travel-v1.json")
    save_manifest(out, manifest)
    by_split = Counter((c.split, c.scenario_id is not None) for c in manifest.cases)
    clusters = {
        s: sorted(
            {c.cluster_id for c in manifest.cases if c.split == s},
            key=lambda x: int(x.rsplit("_", 1)[1]),
        )
        for s in ("development", "validation", "test")
    }
    print(
        json.dumps(
            {
                "hash": manifest.content_hash,
                "cases": len(manifest.cases),
                "not_injectable": not_injectable,
                "by_split": {
                    f"{k[0]}|{'attack' if k[1] else 'benign'}": v
                    for k, v in sorted(by_split.items())
                },
                "clusters": clusters,
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
