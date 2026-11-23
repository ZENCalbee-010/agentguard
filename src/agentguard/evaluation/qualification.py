"""Model qualification on benign tasks (M4).

Purpose: find out whether a local model can use the simulated tools at all, so that a model's
inability is never mistaken for evidence that a defense works (REQ-AGT-4). Only configurations
without an analyzer (B0, B2) are run here; the detector arrives in M5.

Each finished case is appended to a JSONL file immediately, so an interrupted run never leaves
a case that looks like a success: a missing case is reported as missing.
"""

from __future__ import annotations

import json
import math
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from agentguard.agent.model_adapter import ModelAdapter
from agentguard.agent.orchestrator import AgentLimits, AgentOrchestrator, RunStatus
from agentguard.evaluation.benign_tasks import BenignTask, task_utility
from agentguard.policy.schemas import GatewayMode, ReasonCode
from agentguard.sandbox.state import SandboxState, state_diff
from agentguard.stack import build_stack

RECORD_SCHEMA = "m4-qualification-1"
QUALIFICATION_MODES = (GatewayMode.B0, GatewayMode.B2)


def code_version(root: Path) -> dict[str, Any]:
    """Commit SHA of the code under test and whether the working tree has uncommitted changes."""

    def git(*args: str) -> str:
        exe = shutil.which("git")
        if exe is None:
            return ""
        return subprocess.run(  # noqa: S603 - resolved executable, fixed argv, no shell
            [exe, *args], cwd=root, capture_output=True, text=True, check=False
        ).stdout.strip()

    return {"commit": git("rev-parse", "HEAD") or None, "dirty": bool(git("status", "--porcelain"))}


def run_case(
    adapter: ModelAdapter,
    task: BenignTask,
    mode: GatewayMode,
    *,
    limits: AgentLimits,
    version: dict[str, Any],
) -> dict[str, Any]:
    if mode not in QUALIFICATION_MODES:
        raise ValueError(f"qualification runs without an analyzer; unsupported mode {mode}")
    state = SandboxState(files=dict(task.files))
    stack = build_stack(mode, state=state)
    pre = state.snapshot()
    started_at = time.time()
    try:
        result = AgentOrchestrator(adapter, stack, limits).run(task.prompt, task.policy)
    finally:
        stack.gateway.close()
    utility = task_utility(
        task, pre, state, completed=result.status.clean, final_text=result.final_text
    )
    calls = result.calls
    invalid = sum(1 for c in calls if c.reasons == (ReasonCode.INVALID_CALL.value,))
    record = {
        "schema": RECORD_SCHEMA,
        "run_id": uuid.uuid4().hex,
        "started_at": started_at,
        "model": adapter.model_id,
        "model_params": adapter.params,
        "model_digest": adapter.digest(),
        "code": version,
        "mode": mode.value,
        "task_id": task.task_id,
        "data_derived": task.data_derived,
        "policy_hash": result.policy_hash,
        "status": result.status.value,
        "error": result.error,
        "utility": utility,
        "steps": result.steps,
        "model_calls": result.model_calls,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "wall_s": result.wall_s,
        "model_latency_s": result.model_latency_s,
        "proposed_calls": len(calls),
        "invalid_calls": invalid,
        "denied_calls": sum(
            1
            for c in calls
            if c.verdict == "DENY" and c.reasons != (ReasonCode.INVALID_CALL.value,)
        ),
        "executed_calls": len(result.executed_calls),
        "state_fields_changed": sorted(state_diff(pre, state)),
        "final_text": result.final_text[:500],
        "calls": [c.model_dump(mode="json") for c in calls],
        "audit_chain_ok": stack.audit.verify_chain(),
    }
    stack.audit.close()
    return record


def run_qualification(
    adapter: ModelAdapter,
    tasks: Sequence[BenignTask],
    modes: Iterable[GatewayMode],
    out_file: Path,
    *,
    limits: AgentLimits,
    version: dict[str, Any],
    progress: Callable[[str], None] = lambda _msg: None,
) -> list[dict[str, Any]]:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for mode in modes:
        for task in tasks:
            rec = run_case(adapter, task, mode, limits=limits, version=version)
            with out_file.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            records.append(rec)
            progress(
                f"{adapter.model_id} {mode.value} {task.task_id}: {rec['status']} "
                f"utility={rec['utility']} {rec['wall_s']:.1f}s"
            )
    return records


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def summarize(
    records: Sequence[dict[str, Any]], expected: dict[tuple[str, str], int] | None = None
) -> list[dict[str, Any]]:
    """One row per (model, mode). Denominators are stated in the field names."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in records:
        groups.setdefault((r["model"], r["mode"]), []).append(r)
    rows = []
    for (model, mode), rs in sorted(groups.items()):
        n = len(rs)
        proposed = sum(r["proposed_calls"] for r in rs)
        walls = [r["wall_s"] for r in rs]
        statuses = Counter(r["status"] for r in rs)
        rows.append(
            {
                "model": model,
                "mode": mode,
                "cases_finished": n,
                "cases_expected": (expected or {}).get((model, mode), n),
                "utility_success": sum(1 for r in rs if r["utility"]),
                "clean_completion": statuses.get(RunStatus.COMPLETED.value, 0),
                "status_counts": dict(statuses),
                "proposed_calls": proposed,
                "valid_call_rate": (1 - sum(r["invalid_calls"] for r in rs) / proposed)
                if proposed
                else None,
                "cases_with_denial": sum(1 for r in rs if r["denied_calls"] > 0),
                "median_wall_s": statistics.median(walls),
                "p95_wall_s": _p95(walls),
                "mean_input_tokens": statistics.fmean(r["input_tokens"] for r in rs),
                "mean_output_tokens": statistics.fmean(r["output_tokens"] for r in rs),
                "mean_model_calls": statistics.fmean(r["model_calls"] for r in rs),
                "failed_tasks": sorted(r["task_id"] for r in rs if not r["utility"]),
            }
        )
    return rows


def load_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def format_table(rows: Sequence[dict[str, Any]]) -> str:
    head = (
        "model | mode | utility | completed | valid-call rate | cases w/ denial | "
        "median s | p95 s | in/out tok"
    )
    lines = [head, "-" * len(head)]
    for r in rows:
        vcr = "n/a" if r["valid_call_rate"] is None else f"{r['valid_call_rate']:.2f}"
        lines.append(
            f"{r['model']} | {r['mode']} | {r['utility_success']}/{r['cases_finished']} | "
            f"{r['clean_completion']}/{r['cases_finished']} | {vcr} | {r['cases_with_denial']} | "
            f"{r['median_wall_s']:.1f} | {r['p95_wall_s']:.1f} | "
            f"{r['mean_input_tokens']:.0f}/{r['mean_output_tokens']:.0f}"
        )
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    sys.exit("use: agentguard qualify")
