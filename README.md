# AgentGuard v3.1

**AgentGuard: An Intent-Bound Tool Authorization Framework for Mitigating Prompt Injection in AI Agents**
— research prototype (not production software).

AgentGuard places an authorization gateway between an LLM agent and its tools. Each protected tool
call is checked against capabilities scoped to the *trusted user task*; an optional context analyzer
inspects untrusted data flowing into the call. The project measures whether this reduces executed
unauthorized tool actions under indirect prompt injection while preserving benign task utility,
comparing four configurations: B0 (no defense), B1 (detector only), B2 (permissions only),
P1 (detector + permissions).

## Status
Early stage. See [docs/milestones/status.md](docs/milestones/status.md) for the current milestone.
Nothing in this repository should be read as an experimental result until the milestone reports
say so.

## Development setup
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Windows; use .venv/bin/python on Linux/macOS
.venv/Scripts/python -m pytest
.venv/Scripts/mypy
ruff check . && ruff format --check .            # or: python tools/ruff_stdin.py (see CLAUDE.md)
```

## Safety
All tools are simulated against an isolated in-memory/SQLite sandbox. No real email, network
transfer, or destructive operation is performed. Attack strings are synthetic or come from public
research benchmarks and are treated as untrusted data.
