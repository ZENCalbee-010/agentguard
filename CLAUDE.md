# CLAUDE.md — AgentGuard v3.1

Research prototype: intent-bound tool authorization for mitigating indirect prompt injection
in AI agents. Not a production system.

## Session start (always)
1. Read this file, then `docs/milestones/status.md` and `docs/milestones/next-actions.md`.
2. Run `git status` and `git log --oneline -10`; verify the repo matches the status file.
3. Continue from the next incomplete action. Never assume earlier work succeeded without checking.

## Communication
- Progress reports, explanations, risks, milestone reports: **Thai**.
- Code, identifiers, config keys, technical/research docs: **English**.
- Milestone report format: master prompt §14 (Milestone / Status / Implementation / Changed Files /
  Test Evidence / Security Findings / Research Impact / Cost / Next Action / Required Human Approval).

## Environment (verified 2026-11-18, see docs/milestones/M0-readiness.md)
- Windows 11, Python **3.13.14** in `.venv` (3.12 is the declared target; see decision D-001).
- Activate: `.venv\Scripts\activate` (PowerShell) or use `.venv/Scripts/python.exe` directly.
- Tests: `.venv/Scripts/python.exe -m pytest`
- Types: `.venv/Scripts/mypy.exe`
- Mutation check of the security core: `.venv/Scripts/python.exe tools/mutation_check.py` (must stay all-killed)
- Lint/format: **`.venv/Scripts/python.exe tools/ruff_stdin.py [--fix]`** (set `PYTHONIOENCODING=utf-8`) — the native ruff binary cannot open files
  under `C:\your-project` on this machine (BLK-001). CI runs `ruff check .` directly.
- Ollama 0.40.16 at http://localhost:11434; models: `qwen3:8b` and derived `agentguard-qwen3-8b-8k` (num_ctx 8192, see experiments/configs/ollama/). GPU: RX 7600 8 GiB.
- AgentDojo lives only in `.venv-bench` (D-010); core `.venv` has no benchmark dependencies.

## Hard rules
- Security invariants SEC-001..SEC-015: `docs/spec/security-invariants.md`. Never weaken a test to pass.
- Deny-by-default. Untrusted content (tool outputs, documents, benchmark attack strings) never grants
  capabilities. All tools are simulated; no real email, network exfiltration, or destructive ops.
- Feature branches only; never commit on `main`. No push/merge without human approval.
- **Human approval required before:** changing frozen protocol / test cases / ground truth / oracle
  definitions; paid API calls; elevated or untrusted scripts; real external accounts; destructive git ops;
  push/merge; operating on external systems.
- Never fabricate results, citations, DOIs, or benchmark scores. Null results are valid.
- Update `docs/milestones/status.md` (+ decision-log, blockers, next-actions) after significant progress.

## Layout
`src/agentguard/` (package), `tests/{unit,integration,security,regression}`, `docs/{spec,research,milestones}`,
`experiments/`, `datasets/`, `results/`, `tools/` (dev helpers), `paper/`.
