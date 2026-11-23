# M0 — Repository and Environment Audit

Date: 2026-11-18 · Branch: `feat/m0-m1-foundation-spec` · Status: **PASS** (see §7)

## 1. Starting state (observed, not assumed)

| Item | Observation | Evidence |
|---|---|---|
| Working directory | `C:\your-project\agentguard` existed and was **empty** | `ls -la` → no entries |
| Git | Not a repository | `git status` → `fatal: not a git repository` |
| Sibling directory | `C:\your-project\links-project-manager-main` (unrelated project) | `ls ..`; **not touched** |
| Existing AgentGuard code | None. No functionality is claimed to pre-exist. | — |

Because the repository was empty, M0 created only the minimal foundation (§4). No existing file was
overwritten or deleted.

## 2. Environment inventory

| Component | Found | Notes |
|---|---|---|
| OS | Windows 11 Home 10.0.26300 (x86_64); Git Bash (MSYS) + PowerShell 5.1 | Insider-class build number |
| CPU | AMD Ryzen 5 7500F, 6 cores / 12 threads | |
| RAM | 31.6 GiB (33,946,128,384 B) | |
| GPU | AMD Radeon RX 7600, **8.0 GiB VRAM**, ROCm `gfx1102` | Ollama server log: `library=ROCm compute=gfx1102 total="8.0 GiB" available="7.8 GiB"`. (WMI `AdapterRAM` reports 4 GiB — a known 32-bit field cap.) |
| Disk C: | ~592 GiB free | |
| Python | **3.13.14 only** (`py -0p`); no 3.12 | `python`/`python3` on PATH are Microsoft Store stubs; real interpreter at `%LOCALAPPDATA%\Programs\Python\Python313` |
| pip / venv | pip 26.1.2; `venv` works | `uv` not installed |
| Git | 2.54.0.windows.1; global user.name/email configured | |
| GitHub CLI | gh 2.104.0 | No remote configured for this repo |
| Node | v24.15.0 | not required |
| Ollama | 0.40.16, server running at 127.0.0.1:11434 | **No models pulled** (`ollama list` empty). Default `num_ctx=4096` (VRAM-based). |
| Claude Code CLI | not on Git Bash PATH (session runs via VS Code extension) | not required by the code |

### Installed into `.venv` (Python 3.13.14)
`pydantic 2.14.3`, `PyYAML 6.0.3`, `pytest 9.2.0`, `ruff 0.17.5`, `mypy 2.4.1` (+ transitive deps).
Pinned in `pyproject.toml`.

## 3. Missing dependencies and environment limitations

| ID | Item | Impact | Plan |
|---|---|---|---|
| ENV-1 | Python 3.12 not installed | Spec target is 3.12 | D-001: develop on 3.13, declare `requires-python >=3.12`, CI tests 3.12 **and** 3.13. Install 3.12 locally only if a dependency (e.g. AgentDojo) needs it. |
| ENV-2 | No Ollama models | M4 model qualification cannot start | Pull candidates in M4 after checking size vs 8 GiB VRAM. Downloads are large but free; no approval gate. |
| ENV-3 | Ollama default context 4096 tokens | Agent prompts with tool schemas + injected documents can exceed 4k → silent truncation would corrupt results | Set `num_ctx` explicitly per request and log it; verify no truncation in M4. |
| ENV-4 | Native `ruff.exe` gets `Access is denied (os error 5)` reading any file under `C:\your-project` (works on the same file copied to %TEMP%; works via stdin; persists outside the tool sandbox; ACLs normal) | Local lint via direct `ruff check .` fails | BLK-001. Workaround `tools/ruff_stdin.py` (verified to detect real findings). CI runs ruff natively. Likely cause: a Windows security policy (e.g. Controlled Folder Access / AV) on that folder — **unconfirmed**. |
| ENV-5 | No git remote | CI workflows cannot be verified | Pushing requires human approval. CI marked *unverified* until then. |
| ENV-6 | AgentDojo / InjecAgent not installed | Benchmark feasibility unknown | M2. |

## 4. Foundation created in M0

| File | Purpose |
|---|---|
| `.gitignore`, `.gitattributes` | Ignore venv/caches/secrets/DBs; normalize LF |
| `pyproject.toml` | src-layout, pinned deps, pytest markers, ruff, mypy strict |
| `.env.example` | Config documentation, no secrets |
| `CLAUDE.md` | Session-continuity rules and environment notes |
| `README.md` | Minimal description; no result claims |
| `src/agentguard/__init__.py`, `src/agentguard/cli/{__init__,main}.py` | Package + `agentguard version` CLI |
| `tests/unit/test_cli.py` | Smoke tests for the CLI |
| `tools/ruff_stdin.py` | BLK-001 workaround |
| `.github/workflows/ci.yml`, `security.yml` | Lint/type/test on 3.12+3.13; pip-audit; security-marker suite |
| `docs/milestones/*` | This report, status, decision log, blockers, next actions, risk register |

Module directories from the proposed layout (`policy/`, `defense/`, `sandbox/`, …) are **not**
created yet, per the rule against empty modules; they are created by the milestone that implements them.

## 5. Conflicting or ambiguous instructions

| ID | Conflict | Resolution |
|---|---|---|
| C-1 | Target Python 3.12 vs only 3.13 available | D-001 (above) |
| C-2 | Default agent policy "commit only when asked" vs master prompt "small commits on feature branches" | Master prompt explicitly asks for small commits; commits are made on feature branches only, **never pushed/merged** without approval. |
| C-3 | Proposed layout lists many modules vs "avoid empty modules" | Create modules on demand (D-002). |
| C-4 | Editor hook says "greenfield — don't stop for planning" vs master prompt mandatory M1 approval gate | Master prompt governs: stop after M1 for approval of the research spec. |
| C-5 | "Two qualified local models" vs 8 GiB VRAM | Only models that fit 8 GiB (≈ ≤ 9B params at 4-bit) are realistic; qualification in M4 decides. May end with one qualified model — will be reported, not hidden. |
| C-6 | M3 (security core, no LLM) is listed after the M1 approval gate, but it is only partly research-dependent | Treated as gated: M3 policy schema depends on the approved capability/oracle definitions. |
| C-7 | CI workflow required, but pushing needs approval | Workflows written now; verified only after an approved push. |

## 6. Files that must be preserved
- Everything outside `C:\your-project\agentguard` (notably `links-project-manager-main`) — out of scope.
- After freezing (M1 approval / M8): `docs/spec/security-invariants.md`, oracle definitions,
  dataset manifests, experiment protocol, test ground truth — human change control.

## 7. Acceptance criteria

| Criterion | Result |
|---|---|
| Existing repository state documented | PASS — §1, §2 |
| No working files destroyed | PASS — directory was empty; nothing outside it modified |
| Environment limitations identified | PASS — §3 (ENV-1..6) |
| Next feasible milestone clear | PASS — M1 research specification (docs only, no gate before it) |

Quality checks at M0 close: `pytest` 2 passed; `mypy` (strict) clean; `tools/ruff_stdin.py` 0 problems.
Risk register: [risk-register.md](risk-register.md).
