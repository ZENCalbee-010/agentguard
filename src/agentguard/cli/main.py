"""AgentGuard CLI entry point."""

from __future__ import annotations

import argparse
import platform
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from agentguard import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Print AgentGuard and Python versions.")

    q = sub.add_parser("qualify", help="Qualify a local Ollama model on benign tool-use tasks.")
    q.add_argument("--model", required=True, help="Ollama model name")
    q.add_argument("--modes", default="B0,B2", help="comma list from B0,B2 (no analyzer yet)")
    q.add_argument("--tasks", default="", help="comma list of task ids (default: all)")
    q.add_argument("--num-ctx", type=int, default=8192)
    q.add_argument("--think", choices=["default", "on", "off"], default="default")
    q.add_argument("--max-steps", type=int, default=10)
    q.add_argument("--model-timeout", type=float, default=240.0)
    q.add_argument("--out", default="results/raw/m4-qualification")

    m = sub.add_parser(
        "run-matrix", help="Run B0/B1/B2/P1 on benign and own-domain attack scenarios."
    )
    m.add_argument("--model", required=True)
    m.add_argument("--modes", default="B0,B1,B2,P1")
    m.add_argument("--kinds", default="benign,attack")
    m.add_argument("--num-ctx", type=int, default=8192)
    m.add_argument("--think", choices=["default", "on", "off"], default="off")
    m.add_argument("--out", default="results/raw/m5-smoke")
    return parser


def _qualify(args: argparse.Namespace) -> int:
    from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig
    from agentguard.agent.orchestrator import AgentLimits
    from agentguard.evaluation.benign_tasks import BENIGN_TASKS
    from agentguard.evaluation.qualification import (
        code_version,
        format_table,
        load_records,
        run_qualification,
        summarize,
    )
    from agentguard.policy.schemas import GatewayMode

    wanted = {t for t in args.tasks.split(",") if t}
    tasks = [t for t in BENIGN_TASKS if not wanted or t.task_id in wanted]
    if wanted and len(tasks) != len(wanted):
        print(f"unknown task ids: {sorted(wanted - {t.task_id for t in tasks})}", file=sys.stderr)
        return 2
    modes = [GatewayMode(m) for m in args.modes.split(",") if m]
    think = {"default": None, "on": True, "off": False}[args.think]
    adapter = OllamaAdapter(OllamaConfig(model=args.model, num_ctx=args.num_ctx, think=think))
    out = Path(args.out) / f"{args.model.replace(':', '_')}-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    limits = AgentLimits(max_steps=args.max_steps, model_timeout_s=args.model_timeout)
    run_qualification(
        adapter, tasks, modes, out, limits=limits, version=code_version(Path.cwd()), progress=print
    )
    expected = {(args.model, m.value): len(tasks) for m in modes}
    print()
    print(format_table(summarize(load_records(out), expected)))
    print(f"\nraw records: {out}")
    return 0


def _run_matrix(args: argparse.Namespace) -> int:
    from agentguard.agent.model_adapter import OllamaAdapter, OllamaConfig
    from agentguard.agent.orchestrator import AgentLimits
    from agentguard.evaluation.experiment_runner import run_matrix, summarize
    from agentguard.evaluation.qualification import code_version
    from agentguard.policy.schemas import GatewayMode

    think = {"default": None, "on": True, "off": False}[args.think]
    adapter = OllamaAdapter(OllamaConfig(model=args.model, num_ctx=args.num_ctx, think=think))
    out = Path(args.out) / f"{args.model.replace(':', '_')}-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    records = run_matrix(
        adapter,
        out,
        modes=[GatewayMode(m) for m in args.modes.split(",") if m],
        kinds=[k for k in args.kinds.split(",") if k],
        limits=AgentLimits(model_timeout_s=240.0),
        version=code_version(Path.cwd()),
        progress=print,
    )
    print()
    for row in summarize(records):
        print(row)
    print()
    print(f"raw records: {out}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"agentguard {__version__} (python {platform.python_version()})")
        return 0
    if args.command == "run-matrix":
        return _run_matrix(args)
    if args.command == "qualify":
        return _qualify(args)
    return 2  # unreachable: argparse enforces a known command


if __name__ == "__main__":
    sys.exit(main())
