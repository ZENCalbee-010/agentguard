# Project Status

## Current
- **Milestone:** M0–M9 **PASS** (`feat/m8-banking-qwen35`, remote CI verified green); Post-M9 Follow-up **M10** (`feat/m10-v02-and-travel`) **PASS (COMPLETE)** — CI green + `ContextAnalyzer v0.2` (banking dev+test) + AgentDojo `travel` suite (308/308 clean test runs)
- **Branch:** `feat/m10-v02-and-travel` (pushed to `origin`; `feat/m8-banking-qwen35` + `m8-freeze` pushed & CI green; local `main` reset to `f49788c`)
- **Freeze tags:** `m8-freeze` (`a1a105f`), `m10-travel-freeze` (`6ddf92f`)
- **Last updated:** 2026-11-25

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

### 2026-11-24 - M8 Main Experiment & Statistical Analysis (narrower banking study, qwen3.5:9b) - PASS
- Completed: recreated `.venv` and `.venv-bench` on macOS (Apple M2 Pro, Python 3.14.6, D-021), pulled pinned `qwen3.5:9b` (`56671c2ab938`), tagged `m8-freeze` (`a1a105f`), ran 440/440 main experiment runs (`2.95 h`, 423 completed, 17 `step_limit`, 0 infra failures), ran 110/110 M8b B0 noise-floor runs (`0.63 h`, 110 completed), ran `noise_floor.py` and `analyze_main.py --frozen-commit m8-freeze` (exit 0, `INTEGRITY: OK`), wrote `docs/research/m8-main-report.md` and `docs/milestones/M8-report.md`.
- Key results:
  - Noise floor (M8b): 0/110 differences across status/attempt/executed/success/trajectory/tokens (exact 95% CI `[0.000, 0.033]`).
  - Exposure: ADEQUATE (32 B0 attempts in 6/11 user tasks).
  - H1 (confirmatory, B2 vs B0 executed ASR): **SUPPORTED (robust to cluster sign test and two-way bootstrap)** — B0 31/99 (31.3%) vs B2 2/94 (2.1%), diff `+25.5 pp`, McNemar $p = 1.19 \times 10^{-7}$, cluster CI `[0.0909, 0.4468]`, sign test $p = 0.03125$, two-way CI `[0.0707, 0.4945]`; worst-case unclean bound `+24.2 pp`, $p = 1.19 \times 10^{-7}$.
  - H2 (descriptive, P1 vs B2 executed ASR): B2 2/94 vs P1 0/93 (`+2.1 pp`, $p = 0.50$, cluster CI `[0.0, 0.0652]`); both B2 escapes were wildcard `send_money` in `user_task_0`.
  - H3 (descriptive, P1 vs B0 benign utility): 8/9 `valid_13`, 6/7 `strict_11` in all 4 configs (0 benign denials), exact one-sided 95% lower bound `-0.386` / `-0.466`.
  - Attribution finding: `B1` and `P1` produced 110/110 identical trajectories; P1 lost 10 legitimate tasks under attack vs B2 (`-13.3 pp` `valid_13`, `-17.5 pp` `strict_11`, $p = 0.00195$), whereas B2 preserved 100% of clean attack-time utility vs B0 (`+0.0 pp`).
- Tests executed (macOS venvs): core pytest 414 + 26 model_adapter (outside sandbox); bench pytest 89 passed; mypy strict clean (42 files); `tools/ruff_stdin.py` 0 problems (67 files).
- Cost: 0 THB (3.58 h local Apple M2 Pro compute).
- Open / next: M9 Final Audit and Research Package (`docs/research/final-audit.md`, `reproducibility.md`, `paper/draft.md`); user decision on whether to reset local `main` back to `origin/main` (`f49788c`, D-021) and whether to push/merge.

### 2026-11-24 - M9 Final Audit and Research Package - PASS
- Completed: 10-point evidence-based self-audit (`docs/research/final-audit.md`, findings `AUD-001`..`AUD-006`), clean-room reproducibility guide & SHA-256 artifact manifest (`docs/research/reproducibility.md`), 11-section draft research paper with 30 verified citations (`paper/draft.md`), updated `README.md`, and final test/milestone report (`docs/milestones/M9-report.md`).
- Tests & checks executed: core pytest **415 passed, 2 skipped** (`16.14s`); bench pytest **89 passed** (`1.97s`); `tools/mutation_check.py` **42/42 killed**; `mypy --strict` **0 issues (42 files)**; `tools/ruff_stdin.py` **0 problems (67 files)**; offline recomputation of `summary.json` and `noise_floor.json` verified byte-identical against committed outputs.
- Frozen integrity: `git diff m8-freeze HEAD -- SRC_PATHS` empty.
- Cost: 0 THB (cumulative project API spend: 0 / 3,000 THB).
- Remaining human decisions (post-M9): reset local `main` to `origin/main` (`f49788c`), approve adding frozen `experiments/scripts/m6..m8` to ruff `extend-exclude` (`AUD-003`), approve push/merge (`BLK-003`), and optional future follow-up studies (analyzer `v0.2`, additional suites, second qualified model / paid API validation).

### 2026-11-24 - Post-M9 Follow-Up (D-022): CI Green, ContextAnalyzer v0.2, & Travel Suite Qualification
- Track 1 (CI & Git): excluded frozen M6–M8 scripts in `pyproject.toml`, reset local `main` to `f49788c`, pushed `feat/m8-banking-qwen35` + `m8-freeze` to GitHub; both `ci` (Python 3.12/3.13) and `security` workflows passed green (`BLK-003` closed).
- Track 2 (`ContextAnalyzerV2`, `v0.2+07aad61880e0`): dev-split pilot (120 runs) recovered 8/8 `user_task_2` rent updates (`P1` util under attack 16/26 vs 9/26 in v0.1, 0/26 executed). Frozen test split (220 runs `B1`/`P1`): `0/93` executed attacks, cut `P1` `ANALYZER_DENY` by 50% (`40 -> 20`), recovered `user_task_12` & `14`, while isolating all 8 remaining losses to short dual-content file `user_task_13` (`docs/research/m10-v02-report.md`).
- Track 3 (`AgentDojo travel` suite): implemented `travel_policies.py` (`travel-v1`), `agentdojo_travel.py`, `travel-v1.json` (140 cases, 0 F-6 no-op defects, 20/20 injectable, 120/120 B0 parity, 4/120 B2 static ceiling, 112 bench tests passing). B0 qualification on `qwen3.5:9b`: **16/20 (80.0%, Wilson CI `[0.58, 0.92]`)**, `0/118` invalid calls.
- Track 3 execution (2026-11-25, `m10-travel-freeze` `6ddf92f`): ran `308/308` clean test-split runs (`0` unclean, `0` infra failures, `INTEGRITY: OK`). Exposure ADEQUATE (`13` B0 attempts in `5/11` tasks). **H1 (`B2` vs `B0`)**: `10/66 -> 1/66` (`+13.6 pp`, McNemar $p = 0.00391$, cluster CI `[+0.0455, +0.2424]`, sign test `5/11` $p = 0.0625$ — SUPPORTED at case & cluster-bootstrap level). **H2 (`P1 v0.2` vs `B2`)**: exact null (`1/66` vs `1/66`, `0` `ANALYZER_DENY` in `P1`, `0` lost tasks). Utility under attack **improved `+15.1 pp`** (`54/66 -> 64/66`, $p = 0.00195$) under `B2` and `P1`. Single shared escape: `user_task_3|injection_task_5` (in-scope email body exfiltration to authorized recipient). Details: `docs/research/m10-travel-report.md`; integrated into `paper/draft.md` §7.7 and `README.md`.
- Cost: 0 THB total project API spend (0 / 3,000 THB).
- Status: All three approved D-022 tracks complete; ready for PR/merge review or optional paid API external validation if desired.
