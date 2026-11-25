"""Run AgentDojo travel qualification or factorial evaluation (B0/B1/B2/P1) with qwen3.5:9b.

Run in .venv-bench:
  python experiments/scripts/m10/run_travel.py --qualify \
      --out results/raw/m10-travel-qual/qwen3.5_9b-b0-benign.jsonl
  python experiments/scripts/m10/run_travel.py --split development --analyzer v0.2 \
      --modes B0,B1,B2,P1 --experiment-id m10-travel-dev-v02 \
      --out results/raw/m10-travel-dev/qwen3.5_9b-v02.jsonl
"""

from __future__ import annotations

import argparse
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

warnings.filterwarnings("ignore")

from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig  # noqa: E402
from agentguard.benchmarks import agentdojo_travel as at  # noqa: E402
from agentguard.defense.context_analyzer import ContextAnalyzerV0, ContextAnalyzerV2  # noqa: E402
from agentguard.evaluation.manifest import load_manifest  # noqa: E402
from agentguard.evaluation.qualification import code_version  # noqa: E402
from agentguard.evaluation.records import read_records, write_records  # noqa: E402
from agentguard.evaluation.run_control import InfraAbort, InfraGuard, plan_todo  # noqa: E402
from agentguard.policy.schemas import GatewayMode  # noqa: E402

MODEL_DIGEST_PREFIX = "56671c2ab938"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qualify", action="store_true", help="Run B0 benign on all 20 travel tasks")
    ap.add_argument("--split", choices=("development", "validation", "test"), default="development")
    ap.add_argument("--modes", default="B0,B1,B2,P1")
    ap.add_argument("--analyzer", choices=("v0.1", "v0.2"), default="v0.2")
    ap.add_argument("--experiment-id", default="m10-travel")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    manifest = load_manifest(Path("datasets/manifests/travel-v1.json"))
    version = code_version(Path.cwd())
    if version["commit"] is None:
        sys.exit("cannot determine git commit")
    if version["dirty"]:
        sys.exit("working tree is dirty; commit before running")

    adapter = OllamaAdapter(
        OllamaConfig(
            model="qwen3.5:9b",
            num_ctx=12288,
            think=False,
            temperature=0.0,
            seed=0,
            max_output_tokens=1024,
        )
    )
    digest = adapter.digest() or ""
    if not digest.startswith(MODEL_DIGEST_PREFIX):
        sys.exit(f"model digest {digest!r} != pinned {MODEL_DIGEST_PREFIX}...")

    if args.qualify:
        cases = [c for c in manifest.cases if c.scenario_id is None]
        modes = [GatewayMode.B0]
        exp_id = "m10-travel-qual-b0"
    else:
        cases = list(manifest.cases_in(args.split))
        modes = [GatewayMode(m.strip()) for m in args.modes.split(",") if m.strip()]
        exp_id = args.experiment_id

    by_id = {c.case_id: c for c in cases}
    expected = [(m.value, c.case_id) for c in cases for m in modes]
    out = Path(args.out)
    existing = read_records(out) if out.exists() else []
    todo, exhausted = plan_todo(expected, existing)
    out.parent.mkdir(parents=True, exist_ok=True)

    suite = at.load_suite()
    registry = at.build_registry(suite)
    factory = ContextAnalyzerV2 if args.analyzer == "v0.2" else ContextAnalyzerV0
    guard = InfraGuard()
    started = time.monotonic()
    counts: Counter[str] = Counter()
    print(
        f"{len(todo)} runs to do (exp={exp_id}, analyzer={args.analyzer}, "
        f"commit={str(version['commit'])[:8]}, exhausted={len(exhausted)})",
        flush=True,
    )
    try:
        for idx, (mode_id, case_id) in enumerate(todo, 1):
            case = by_id[case_id]
            mode = GatewayMode(mode_id)
            parts = case_id.split("|")
            rec = at.run_travel_case(
                adapter,
                mode,
                parts[0],
                parts[1] if case.scenario_id else None,
                experiment_id=exp_id,
                version=version,
                suite=suite,
                registry=registry,
                max_iters=12,
                timeout_s=300.0,
                analyzer_factory=factory,
            )
            write_records(out, [rec])
            counts[rec.run_status] += 1
            print(
                f"[{idx}/{len(todo)} {(time.monotonic() - started) / 60:.0f} min] "
                f"{mode_id} {case_id}: {rec.run_status} {rec.latency_s:.1f}s",
                flush=True,
            )
            guard.observe(rec)
    except InfraAbort as exc:
        sys.exit(f"ABORT: {exc}")
    print(f"done: {dict(counts)}", flush=True)


if __name__ == "__main__":
    main()
