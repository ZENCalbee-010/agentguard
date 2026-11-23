# Project Status

## Current
- **Milestone:** M8 - Main experiment (narrower banking study, qwen3.5:9b) -> **FROZEN, run pending** (user chose this scope; the agent's reading of that choice as approval of E is D-020 and is open to correction)
- **Branch:** `feat/m8-banking-qwen35` (stacked on M7d; not pushed; no remote)
- **Freeze tag:** `m8-freeze` (SHA recorded below once created)
- **Last updated:** 2026-11-19

## Log

### 2026-11-18 — M0 Repository & Environment Audit — PASS
- Completed: environment inventory, empty-repo foundation, git init (`main` holds only `.gitignore`),
  venv (Python 3.13.14), pinned dev tools, CLI stub, CI workflows (unverified), milestone docs, risk register.
- Changed files: see `docs/milestones/M0-readiness.md` §4.
- Tests executed: `pytest` → 2 passed; `mypy` strict → no issues (3 files); `tools/ruff_stdin.py` → 0 problems
  (5 files); wrapper verified to report findings on a deliberately bad file.
- Unresolved: BLK-001 (native ruff file access), BLK-003 (no remote → CI unverified), ENV-2 (no models).

### 2026-11-18 — M1 Research Specification — DRAFT COMPLETE, awaiting approval
- Completed: requirements, threat model, 15 security invariants with planned positive/negative tests,
  architecture with exact B0/B1/B2/P1 gateway semantics, acceptance criteria + traceability, RQs/hypotheses/
  metrics/denominators/statistical plan, related-work matrix (32 sources, bibliographic fields verified
  on 2026-11-18) with research-gap matrix and novelty status.
- Key finding: mechanism-level novelty is **unsupported** (IGTA arXiv:2606.22916; DRIFT arXiv:2506.12104).
  Proposed framing: empirical attribution study (D-008).
- Tests executed: no code changes beyond M0; checks re-run green.
- Required approvals: D-005..D-008, δ margin, REQ-AGT-4 threshold (see `next-actions.md`).

Current commit SHA: see `git log -1` (recorded in the milestone report).

### 2026-11-18 — M1 approval
- User approved D-005..D-008. δ = 10 pp and REQ-AGT-4 (≥ 50% benign utility) are **not** approved yet (D-009).

### 2026-11-18 — M2 Benchmark Feasibility — PASS
- Completed: AgentDojo 0.1.35 / suite v1.2.2 installed in isolated `.venv-bench`; 35 injection tasks classified
  (25 direct, 9 adapted-pending, 1 out of scope); InjecAgent @ f19c9f2 assessed (attempt-rate only);
  native no-LLM smoke test; no-op negative control on all 35 oracles (35/35 false); ground-truth positive
  control 27/35; five benchmark defects documented (F-1..F-5).
- LLM smoke test (added after model download): qwen3:8b via Ollama /v1 drove the native pipeline on banking user_task_0 (benign utility true; with injection_task_0 the native oracle reported the injection achieved). Single case, existence proof only. Context 8192, 100% GPU, no truncation.
- Changed files: `docs/research/{benchmark-compatibility,dataset-selection}.md`, `docs/research/evidence/*`,
  `experiments/scripts/m2/*`, `experiments/configs/ollama/*`, `pyproject.toml` (ruff exclude), tracking docs.
- Tests executed: `pytest` 2 passed; ruff (stdin) 0 problems; evidence scripts run with `python -I` in `.venv-bench`.
- Required approvals before M7: oracle adaptations F-2/F-3 (new oracle definitions); δ; REQ-AGT-4 threshold.

### 2026-11-18 — M3 Security Core and Minimal Vertical Slice — PASS
- Completed: policy schemas, capability store + trusted channel, tool registry/normalizers, deny-by-default policy
  engine, authorization gateway (B0/B1/B2/P1), sandbox state/mock tools/atomic executor, hash-chained SQLite
  audit log, state-only oracle, composition root, analyzer test doubles. Details: `docs/milestones/M3-report.md`.
- Tests executed: pytest 185 passed (security 94, integration 9, regression 2); mypy strict clean (25 files);
  ruff via stdin wrapper 0 problems (37 files); mutation check 22/22 killed.
- Defects found by own tests and fixed: RF-001 (High, amount overflow escaped as exception), RF-002 (Low, Unicode
  case mapping). Limitations S-1..S-10 documented; none claimed as fixed.
- Not verified: native ruff, CI, AgentDojo-adapter semantics (M5/M6).
- Required approvals: none for M3; pending since M1/M2: delta, REQ-AGT-4 threshold, oracle adaptations F-2/F-3/F-4.

### 2026-11-19 - M4 Agent Runtime - PASS (partial qualification)
- Completed: model adapter + Ollama adapter, agent loop with limits, scripted model, 11 benign tasks, qualification runner/CLI, any_value wildcard (D-012..D-014).
- Tests: pytest 284 passed; mypy strict clean; ruff 0; mutation 32/32. qwen3:8b: thinking off 11/11, thinking default 8/11 (B0 = B2). Details: `docs/milestones/M4-report.md`.
- Open: second model (BLK-005); R-21 (data-derived arguments), R-22 (generation settings).
- Approvals: none new; D-009 items still pending before M7.

### 2026-11-19 - M5 Analyzer and four configurations - PASS (own-domain)
- Completed: analyzer v0.1 (a priori parameters), shared runner, 20 attack scenarios, 124-run live smoke. Details: `docs/milestones/M5-report.md`.
- Tests: pytest 316; mypy strict clean; ruff 0; mutation 36/36.
- Findings: analyzer over-blocks legitimate calls once injected text is in context (utility under attack 10/20 vs 18/20 for B2); stealth substitution beats all configs on wildcard policies.
- Not done: AgentDojo adapter, F-3 oracle adaptation, second model.

### 2026-11-19 - M6 Evaluation infrastructure - PARTIAL
- Completed: record schema + strict storage + CSV, metrics with denominators, statistics (Wilson, exact McNemar, Holm, cluster bootstrap), manifests with cluster splits, config schema, lock file. AC-M6-01 verified on real M5 raw data.
- Tests: pytest 333 (also in a fresh venv); mypy strict clean; ruff 0; mutation 42/42. Details: `docs/milestones/M6-report.md`.
- Open: AgentDojo adapter (R-20), second model (BLK-005), CI unverified (BLK-003).

### 2026-11-19 - M6 AgentDojo banking adapter - PASS (banking only)
- Completed: registry from AgentDojo schemas, gateway-controlled execution, 16 frozen task policies (hash 3efdfa4e...), static policy-coverage matrix (B0 144/144, B2 12/144 goal-achieved pairs), end-to-end LLM plumbing smoke (n=1 per cell).
- Tests: core 384 passed + 1 skipped; bench 42 passed; mypy/ruff clean. Details: `docs/milestones/M6-report.md`.
- Open: other suites, adapter mutation testing, F-2/F-3/F-4 approvals, delta/REQ-AGT-4 approvals, second model, CI unverified.


### 2026-11-19 - M7 Pilot (AgentDojo banking, development split) - COMPLETE, NO-GO recommended
- Done: sealed manifest (160 cases), frozen pilot config, runner producing formal records, 120 pilot runs on a clean tree, B0 benign qualification on all 16 tasks, analysis, budget, GO/NO-GO. Details: `docs/research/pilot-report.md`, `experiment-budget.md`, `pilot-go-no-go.md`.
- Results (descriptive only): B0 executed 8/26, B1 0/27, B2 0/26, P1 0/26; P1 trajectories equal B2 in 30/30; 20.0 s/run; 0 THB.
- Findings: F-6 (do-nothing agent passes 5/16 utility oracles), RF-003 fixed (registry rejections are not defense denials), D-015 fidelity fix, benign B0 4/11 on discriminating tasks, text-only policies deny harmless reads.
- Tests: core 388 passed + 2 skipped; bench 56 passed; mypy strict and ruff clean.
- Needs the user: options A-F in `pilot-go-no-go.md`; delta; benign threshold; thinking setting; F-2/F-3/F-4.

### 2026-11-19 - M7b options A + B + D - DONE
- Done: banking-v2 policies (v1 preserved), utility strata, llama3.1:8b qualification, v2 re-pilot (120 runs, clean tree), comparison. Details: `docs/research/pilot-v2-report.md`, GO/NO-GO addendum.
- Results (descriptive): B0 8/26 executed, B1/B2/P1 0/27; P1 = B2 (30/30); B0 and B1 reproduce v1 30/30; malformed-call cascade 32 -> 3; qwen3:8b 5/13 on valid tasks, llama3.1:8b 2/13.
- Tests: core 391 passed + 2 skipped; bench 89 passed; mypy strict and ruff clean.
- Open: C (more suites), D2 (stronger model), G (paid validation), E (delta/threshold/thinking), F (F-4).

### 2026-11-19 - M7c D2 (stronger local model) - DONE
- Done: verified model choice (qwen3.5:9b), qualification 9/13 on valid tasks, 120-run pilot on a clean tree. Details: `docs/research/pilot-qwen35-report.md`.
- Results (descriptive): B0 7/27 executed (all in user task 2), B1/B2 0/27, P1 0/26; utility under attack B0 17/27, B2 17/27, B1 9/27, P1 9/26; P1's 9 analyzer denials were all the legitimate rent update.
- Open: E (delta, threshold, thinking), C (more suites), second qualified model (gemma4:e4b / lfm2.5), G (paid validation), F (F-4).

### 2026-11-19 - M7d second model for RQ4 (gemma4:e4b) - DONE, not qualified
- Done: pulled gemma4:e4b-it-q4_K_M, qualified in B0 (think off and on). 5/13 valid tasks in both, 6-7 of 16 runs made no tool call. Details: `docs/research/qualification-gemma4.md`.
- Consequence: RQ4 still has one qualified model (qwen3.5:9b). Recommendation unchanged: conditional GO for the narrower banking study only.
- Open: E, C, G, F, lfm2.5 (untried), push/remote (BLK-003).

### 2026-11-19 - M8 preparation (narrower banking study, qwen3.5:9b) - FROZEN, run pending
- Done: pre-registered analysis plan, frozen test-split config (110 cases x 4 = 440 runs), guarded runner, integrity-gated analysis, exact non-inferiority test with exact operating characteristics, noise-floor design. Adversarial pre-registration review (5 lenses, 38 findings, 6 major) applied. Details: `docs/research/m8-analysis-plan.md`.
- Gates: pytest all green, ruff 0, mypy strict clean.
- Not run yet: the 440 runs (about 6 h) and the B0 noise-floor run (about 1.5 h).
