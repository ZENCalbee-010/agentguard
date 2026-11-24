"""Run AgentDojo banking cases with ContextAnalyzerV2 (v0.2, post-M8 follow-up D-022).

Run in .venv-bench:
  python experiments/scripts/m10/run_banking_v02.py --split development --modes B1,B2,P1 \
      --out results/raw/m10-banking-v02-dev/qwen3.5_9b-think-off.jsonl
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
from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.benchmarks.agentdojo_runner import run_case  # noqa: E402
from agentguard.benchmarks.banking_policies import POLICY_VERSION  # noqa: E402
from agentguard.defense.context_analyzer import AnalyzerConfigV2, ContextAnalyzerV2  # noqa: E402
from agentguard.evaluation.manifest import load_manifest  # noqa: E402
from agentguard.evaluation.qualification import code_version  # noqa: E402
from agentguard.evaluation.records import read_records, write_records  # noqa: E402
from agentguard.evaluation.run_control import InfraAbort, InfraGuard, plan_todo  # noqa: E402
from agentguard.policy.schemas import GatewayMode  # noqa: E402

MODEL_DIGEST_PREFIX = "56671c2ab938"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=("development", "validation", "test"), required=True)
    ap.add_argument("--modes", default="B1,P1")
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    manifest = load_manifest(Path("datasets/manifests/banking-v1.json"))
    modes = [GatewayMode(m.strip()) for m in args.modes.split(",") if m.strip()]
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

    out = Path(args.out)
    existing = read_records(out) if out.exists() else []
    cases = list(manifest.cases_in(args.split))
    by_id = {c.case_id: c for c in cases}
    expected = [(m.value, c.case_id) for c in cases for m in modes]
    todo, exhausted = plan_todo(expected, existing)
    out.parent.mkdir(parents=True, exist_ok=True)

    suite = ab.load_suite()
    registry = ab.build_registry(suite)
    cfg_v2 = AnalyzerConfigV2()
    guard = InfraGuard()
    started = time.monotonic()
    counts: Counter[str] = Counter()
    print(
        f"{len(todo)} runs to do (split={args.split}, "
        f"analyzer={cfg_v2.version}+{cfg_v2.config_hash}, "
        f"commit={str(version['commit'])[:8]}, exhausted={len(exhausted)})",
        flush=True,
    )
    try:
        for idx, (mode_id, case_id) in enumerate(todo, 1):
            case = by_id[case_id]
            mode = GatewayMode(mode_id)
            parts = case_id.split("|")
            rec = run_case(
                adapter,
                mode,
                parts[0],
                parts[1] if case.scenario_id else None,
                experiment_id=args.experiment_id,
                version=version,
                suite=suite,
                registry=registry,
                max_iters=10,
                timeout_s=300.0,
                policy_version=POLICY_VERSION,
                analyzer_factory=ContextAnalyzerV2,
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
