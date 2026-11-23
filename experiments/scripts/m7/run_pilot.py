"""Run the banking pilot exactly as frozen in experiments/configs/m7-pilot.yaml. Resumable.

Run in .venv-bench:
  python experiments/scripts/m7/run_pilot.py --config experiments/configs/m7-pilot.yaml \\
      --out results/raw/m7-pilot/run.jsonl
Re-running with the same --out skips cases that already have a record (an interrupted run is
resumed, never double counted).
"""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig  # noqa: E402
from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.benchmarks.agentdojo_runner import run_case  # noqa: E402
from agentguard.benchmarks.banking_policies import POLICY_VERSION  # noqa: E402
from agentguard.defense.context_analyzer import AnalyzerConfig  # noqa: E402
from agentguard.evaluation.config import load_config  # noqa: E402
from agentguard.evaluation.manifest import load_manifest  # noqa: E402
from agentguard.evaluation.qualification import code_version  # noqa: E402
from agentguard.evaluation.records import read_records, write_records  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--config", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--limit", type=int, default=0, help="debug only: first N cases per configuration")
args = ap.parse_args()

cfg = load_config(Path(args.config))
manifest = load_manifest(Path(cfg.manifest_path))
cfg.check_manifest(manifest)
if cfg.analyzer_config_hash != AnalyzerConfig().config_hash:
    sys.exit("analyzer configuration differs from the frozen one")
if len(cfg.models) != 1 or cfg.repetitions != 1:
    sys.exit("this runner implements one model and one repetition")
cases = list(manifest.cases_in(cfg.split))
if args.limit:
    cases = cases[: args.limit]
out = Path(args.out)
done = {(r.config_id, r.case_id) for r in read_records(out)} if out.exists() else set()

spec = cfg.models[0]
adapter = OllamaAdapter(
    OllamaConfig(
        model=spec.name,
        num_ctx=spec.num_ctx,
        think=spec.think,
        temperature=spec.temperature,
        seed=spec.seed,
        max_output_tokens=spec.max_output_tokens,
    )
)
version = code_version(Path.cwd())
suite = ab.load_suite()
registry = ab.build_registry(suite)
todo = [(m, c) for m in cfg.configs for c in cases if (m.value, c.case_id) not in done]
print(f"{len(todo)} runs to do ({len(done)} already recorded); config hash {cfg.config_hash[:12]}", flush=True)
for mode, case in todo:
    parts = case.case_id.split("|")
    rec = run_case(
        adapter, mode, parts[0], parts[1] if case.scenario_id else None,
        experiment_id=cfg.experiment_id, version=version, suite=suite, registry=registry,
        max_iters=cfg.max_steps, timeout_s=cfg.max_wall_s, policy_version=cfg.policy_version or POLICY_VERSION,
    )  # fmt: skip
    write_records(out, [rec])
    print(
        f"{mode.value} {case.case_id}: {rec.run_status} success={rec.task_success} "
        f"attempted={rec.attack_attempted} executed={rec.attack_executed} {rec.latency_s:.1f}s "
        f"{rec.input_tokens}/{rec.output_tokens} tok",
        flush=True,
    )
