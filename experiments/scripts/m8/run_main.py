"""Run the M8 main experiment exactly as frozen in a config, with guards for a long unattended run.

Run in .venv-bench:
  python experiments/scripts/m8/run_main.py --config experiments/configs/m8-banking-qwen35.yaml \
      --out results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl

Differences from the M7 pilot runner (docs/research/m8-analysis-plan.md, section 7):
* refuses to start on a dirty working tree or when the commit cannot be determined, so every record
  carries `code_dirty = false`; to resume, commit the partial raw file first (a data checkpoint);
* checks the Ollama model digest against the pinned one before the first case;
* cases run in case-major order (all four configurations of a case before the next case), so no
  configuration is confounded with the time of the run;
* resume skips every case that already has a record, EXCEPT cases whose attempts all failed for
  infrastructure reasons (model_timeout, model_error): those are re-run once more, in a second pass at
  the end of the run and again on resume. Both attempts are kept; the analysis uses the latest;
* writes the failing records, then aborts after 3 consecutive infrastructure failures, so a server
  outage costs at most 3 attempts instead of one junk record per remaining case;
* refuses a records file that belongs to another experiment, a damaged records file, and a second
  concurrent instance;
* the console shows progress only (index, elapsed time, configuration, case, run status, latency), never
  attack or task outcomes, so that the plan's no-interim-analysis rule holds.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

warnings.filterwarnings("ignore")

from pydantic import ValidationError  # noqa: E402

from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig  # noqa: E402
from agentguard.benchmarks import agentdojo_banking as ab  # noqa: E402
from agentguard.benchmarks.agentdojo_runner import run_case  # noqa: E402
from agentguard.benchmarks.banking_policies import POLICY_VERSION  # noqa: E402
from agentguard.defense.context_analyzer import AnalyzerConfig  # noqa: E402
from agentguard.evaluation.config import load_config  # noqa: E402
from agentguard.evaluation.manifest import load_manifest  # noqa: E402
from agentguard.evaluation.qualification import code_version  # noqa: E402
from agentguard.evaluation.records import read_records, write_records  # noqa: E402
from agentguard.evaluation.run_control import InfraAbort, InfraGuard, plan_todo  # noqa: E402

MODEL_DIGEST_PREFIX = "56671c2ab938"  # qwen3.5:9b as pulled and qualified (M7c); pinned in the M8 plan

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
if (cfg.policy_version or POLICY_VERSION) != "banking-v2":
    sys.exit("the M8 protocol freezes policy banking-v2")

version = code_version(Path.cwd())
if version["commit"] is None:
    sys.exit("cannot determine the git commit (git missing or not a repository)")
if version["dirty"]:
    sys.exit("working tree is not clean: commit everything (including any partial raw file) before running")
out = Path(args.out)
try:
    existing = read_records(out) if out.exists() else []
except ValidationError as exc:
    sys.exit(
        f"{out} is damaged ({exc.error_count()} invalid line(s), probably a truncated last line after a crash). "
        "Plan section 7: copy the damaged last line to a side file, remove exactly that line, commit the file as "
        "the checkpoint and report the repair."
    )
if any(r.experiment_id != cfg.experiment_id for r in existing):
    sys.exit(f"{out} contains records of another experiment; refusing to append")

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
digest = adapter.digest() or ""
if not digest.startswith(MODEL_DIGEST_PREFIX):
    sys.exit(f"model digest {digest!r} is not the pinned {MODEL_DIGEST_PREFIX}... (or Ollama is unreachable); refusing to run")

cases = list(manifest.cases_in(cfg.split))
if args.limit:
    cases = cases[: args.limit]
by_id = {c.case_id: c for c in cases}
expected = [(m.value, c.case_id) for c in cases for m in cfg.configs]  # case-major: arms interleave
out.parent.mkdir(parents=True, exist_ok=True)
lock = out.with_suffix(".lock.tmp")  # *.tmp under results/raw is git-ignored
try:
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
except FileExistsError:
    sys.exit(f"{lock} exists: another run is active or crashed; remove it only after checking")
os.close(fd)

suite = ab.load_suite()
registry = ab.build_registry(suite)
guard = InfraGuard()
started = time.monotonic()
status_counts: Counter[str] = Counter()


def run_batch(todo: list[tuple[str, str]], label: str) -> None:
    for done, (mode_id, case_id) in enumerate(todo, 1):
        case = by_id[case_id]
        mode = next(m for m in cfg.configs if m.value == mode_id)
        parts = case_id.split("|")
        rec = run_case(
            adapter, mode, parts[0], parts[1] if case.scenario_id else None,
            experiment_id=cfg.experiment_id, version=version, suite=suite, registry=registry,
            max_iters=cfg.max_steps, timeout_s=cfg.max_wall_s, policy_version=cfg.policy_version or POLICY_VERSION,
        )  # fmt: skip
        write_records(out, [rec])
        status_counts[rec.run_status] += 1
        print(
            f"[{label} {done}/{len(todo)} {(time.monotonic() - started) / 60:.0f} min] {mode_id} {case_id}: "
            f"{rec.run_status} {rec.latency_s:.1f}s",
            flush=True,
        )
        guard.observe(rec)  # raises InfraAbort after 3 infrastructure failures in a row


todo, exhausted = plan_todo(expected, existing)
print(
    f"{len(todo)} runs to do ({len(existing)} attempts already recorded; {len(exhausted)} cases exhausted "
    f"by infrastructure failures); config hash {cfg.config_hash[:12]}; commit {str(version['commit'])[:8]}",
    flush=True,
)
try:
    run_batch(todo, "pass 1")
    retry, exhausted = plan_todo(expected, read_records(out))
    if retry:
        print(f"{len(retry)} cases failed for infrastructure reasons; re-running them once", flush=True)
        run_batch(retry, "retry")
        retry, exhausted = plan_todo(expected, read_records(out))
except InfraAbort as exc:
    print(f"ABORT: {exc}. Fix the server, commit the partial raw file, and start again to resume.", flush=True)
    sys.exit(3)
finally:
    with contextlib.suppress(OSError):
        lock.unlink()
print(f"run finished: statuses this session {dict(status_counts)}; pending retries {len(retry)}; exhausted {len(exhausted)}", flush=True)
sys.exit(4 if retry else 0)
