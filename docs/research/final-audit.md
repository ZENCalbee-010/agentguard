# Final Audit Report — AgentGuard v3.1 (Milestone M9)

Date: 2026-11-24 | Branch: `feat/m8-banking-qwen35` | Freeze tag: `m8-freeze` (`a1a105f25d56ef1244887cf901091c4f4ab811a3`)
Auditor role: Self-review and evidence-based audit (Master Prompt §10 & M9). **Disclosure (R-10):** This is an evidence-based self-audit by the implementing agent, *not* an independent external human security audit.

---

## 1. Executive Summary

- **Architecture & Requirements:** Implemented end-to-end as specified in `docs/spec/architecture.md` and `docs/spec/requirements.md` for the approved narrower banking study (`D-005..D-008`, `D-017..D-020`). Zero frozen files in `SRC_PATHS` changed after `m8-freeze`.
- **Security Invariants (`SEC-001`–`SEC-015`):** All 15 invariants retain positive and negative automated tests under `tests/security/`, verified alongside `42/42` killed mutations in `tools/mutation_check.py`, strict `mypy` (42 source files, 0 issues), `tools/ruff_stdin.py` (67 files, 0 problems), and `89/89` AgentDojo banking adapter tests.
- **Experimental Integrity:** `experiments/scripts/m8/analyze_main.py --frozen-commit m8-freeze` passed with exit code `0` (`INTEGRITY: OK`, `440/440` records, `0` dirty, `0` infra failures, pinned digest `56671c2ab938...`). M8b noise floor confirmed `0/110` disagreements across status, attempt, execution, task success, trajectory, and tokens.
- **Critical Audit Findings:** 0 critical security-bypass defects in the core gateway; **1 Major design/utility finding** (AUD-001: heuristic analyzer v0.1 globally denies protected calls after untrusted injection text, causing B1==P1 trajectory collapse and 10 lost legitimate tasks under attack), **2 Medium operational/reproducibility findings** (AUD-002: Windows-to-macOS platform migration before M8; AUD-003: native `ruff check .` reports 174 findings in frozen `experiments/scripts/`), and **3 Low/Governance findings** (AUD-004: remote CI unverified; AUD-005: `main` branch holds data commit `f79fa70` from external HEAD switch; AUD-006: `tools/mutation_check.py` covers core modules only, not `benchmarks/`).

---

## 2. Ten-Point M9 Audit Matrix

| Area | Verification Evidence | Status | Caveats / Unverified Scope |
|---|---|---|---|
| 1. Architecture vs Requirements | `src/agentguard/` reviewed against `docs/spec/architecture.md` & `requirements.md`; single gateway intercept point (`authorization_gateway.py:261-321`); AST import boundary verified for `sandbox/` and `evaluation/oracle.py` | **PASS** | `workspace`, `travel`, `slack` suites out of scope for this narrower study; `REQ-AGT-4` 50% threshold satisfied by point estimate (`9/13`, Wilson `0.42–0.87`) |
| 2. Security Invariants (`SEC-001..015`) | All 15 positive + negative tests in `tests/security/test_invariants.py`, `test_boundaries.py`, `test_review_findings.py`; `42/42` mutations killed (`tools/mutation_check.py`) | **PASS** | In-process Python boundary (`S-1`, Threat Model A1); hung analyzer thread pool cap (`S-2`) |
| 3. Known Defects (`RF-001..003`, `F-1..F-6`) | Confirmed core defects `RF-001` (amount overflow), `RF-002` (Unicode case folding), `RF-003` (invalid calls miscounted as denials) all fixed with regression tests in `tests/regression/test_regressions.py`; benchmark defects `F-1..F-6` documented and handled transparently | **PASS** | `F-4` (banking injection tasks 0/1/3 looser native predicate) preserved unmodified per protocol; `F-6` handled via `valid_13`/`strict_11` strata |
| 4. Test Quality & Static Analysis | Full core pytest green (see `M9-report.md`); `tests/bench_agentdojo` `89 passed`; `mypy --strict` `0` issues (42 files); `tools/ruff_stdin.py` `0` problems (67 files); `tools/mutation_check.py` `42/42` killed | **PASS (with AUD-003, AUD-006)** | `test_unresponsive_server_raises_model_timeout` requires loopback socket permission; `experiments/scripts/` has 174 style findings under raw `ruff check .`; adapter not covered by `mutation_check.py` |
| 5. Benchmark Compatibility Claims | `docs/research/benchmark-compatibility.md` matches installed `agentdojo==0.1.35` / `v1.2.2`; banking ground truth `144/144` parity in B0; InjecAgent accurately classified as attempt-rate-only (not run) | **PASS** | Only `banking` suite adapted and tested live |
| 6. Experimental Integrity | `analyze_main.py --frozen-commit m8-freeze` → `INTEGRITY: OK`; `git diff m8-freeze HEAD -- SRC_PATHS` empty; M8b noise floor `0/110`; no interim peeking before completion | **PASS (with AUD-002, AUD-005)** | Platform shift Windows→macOS (D-021, R-33); non-blind policy authoring (R-24) |
| 7. Statistical Methods | Pre-registered in `docs/research/m8-analysis-plan.md` after 5-lens adversarial review (38 findings); exact McNemar, user-task cluster bootstrap (`seed=20261119`, 10k), cluster sign test, two-way bootstrap, leave-one-cluster-out, per-arm unclean bounding sensitivity, exact Berger-Boos H3 interval (`m8-h3-operating-characteristics.json`) | **PASS** | Single repetition (mitigated by M8b `0/110`); H2 and H3 appropriately downgraded to descriptive before running test split |
| 8. Reproducibility Instructions | `docs/research/reproducibility.md` lists exact freeze commit, SHA-256 hashes of all raw/metrics artifacts, pinned core and bench env specs, and offline recomputation commands | **PASS** | Cross-GPU floating-point differences possible at `temp=0` (R-33) |
| 9. Related Work & Citations | `docs/research/related-work-matrix.md` and `paper/draft.md` §11 use only bibliographic entries verified on 2026-11-18 (arXiv IDs, confirmed venues or "arXiv preprint"); zero fabricated DOIs or third-party scores | **PASS** | Full-text reading of IGTA, DRIFT, Progent, LlamaFirewall still recommended before journal submission (currently abstract-level except LlamaFirewall §4) |
| 10. Research Contribution Claims | Novelty of mechanism explicitly marked **Unsupported** (`D-008`); framed as empirical paired factorial attribution study; negative P1-vs-B2 utility trade-off and untested RQ4 reported honestly | **PASS** | Verified strictly for `qwen3.5:9b` on AgentDojo banking v1.2.2 |

---

## 3. Formal Audit Findings Register (§10 Format)

### AUD-001 — Context Analyzer v0.1 Over-Blocks Legitimate Protected Calls Under Attack
- **Severity:** Major (Research/Design Finding — *not* a security bypass)
- **File and line:** `src/agentguard/defense/context_analyzer.py:134-147`
- **Evidence:** In M8 (`results/metrics/m8-banking-qwen35/summary.json`), `P1` lost `10` legitimate tasks under attack that `B2` completed (`-13.3 pp` `valid_13`, `-17.5 pp` `strict_11`, McNemar $p = 0.00195$, `strict_11` cluster CI `[-0.473, -0.016]`), with `10/10` carrying `ANALYZER_DENY`; `B1` and `P1` produced `110/110` identical trajectories.
- **Root cause:** When `untrusted[-1]` contains $\ge 2$ imperative regex matches (`S2 = 1.0`, `S4 = 1.0`), any protected tool call scores $0.4(1.0) + 0.2(1.0) = 0.6 \ge \text{threshold}(0.6)$ even when `S1 = 0` (arguments came from trusted prompt) and `S3 = 0` (tool matches user intent). Furthermore, `DEFAULT_TOOL_VERBS` (`context_analyzer.py:52-57`) lacks entries for four banking mutation tools (`schedule_transaction`, `update_scheduled_transaction`, `update_password`, `update_user_info`).
- **Impact:** Severe attack-time utility degradation (`-13.3` to `-17.5 pp`) for only 2 prevented wildcard attacks ($p = 0.50$).
- **Recommended correction:** Keep `v0.1` frozen for M8 reproducibility; in future work (`v0.2`, tuned on development split only), gate `ANALYZER_DENY` on argument-level taint (`S1 > 0` or wildcard parameter binding) rather than context-wide `S2 + S4` alone.
- **Acceptance criteria:** `v0.2` preserves `B2`-level utility under attack on dev split while retaining wildcard attack blocking.
- **Status:** Open (Documented as primary empirical finding in `m8-main-report.md` and `paper/draft.md`; R-28).

### AUD-002 — Execution Platform Migration Between Pilot (M7d) and Main Experiment (M8)
- **Severity:** Medium (Reproducibility / Comparability)
- **File and line:** `docs/milestones/decision-log.md:26` (D-021), `docs/milestones/risk-register.md:40` (R-33)
- **Evidence:** M0–M7d ran on Windows 11 / AMD RX 7600 8 GiB / Python 3.13.14; M8 and M8b ran on macOS arm64 Apple M2 Pro / Python 3.14.6. B0 benign score on the 11 test user tasks shifted from `6/9` valid (M7c Windows qualification) to `8/9` valid (M8 macOS).
- **Root cause:** Workspace migrated to macOS host prior to M8 execution; GPU backend differences (ROCm/Vulkan vs Metal) change floating-point tie-breaking at `temperature = 0`.
- **Impact:** Cross-platform bit-reproducibility is not guaranteed; however, *within-study internal validity is unaffected* because all four M8 arms ran interleaved case-by-case on the same machine and M8b showed `0/110` run-to-run disagreements.
- **Recommended correction:** Report platform shift explicitly in all reports and paper limitations (done); keep exact pinned model digest (`56671c2ab938...`) and package freeze (`agentdojo==0.1.35`).
- **Acceptance criteria:** Disclosed in `m8-main-report.md`, `reproducibility.md`, `paper/draft.md`, and `risk-register.md`.
- **Status:** Accepted / Mitigated.

### AUD-003 — Frozen Experiment Scripts Fail Raw `ruff check .` (174 Style Findings)
- **Severity:** Medium (CI / Lint Hygiene)
- **File and line:** `experiments/scripts/m6/*.py`, `experiments/scripts/m7/*.py`, `experiments/scripts/m8/*.py` (verified via `.venv/bin/ruff check . --statistics`: 169 `E501`, 3 `I001`, 1 `RUF100`, 1 `F841`)
- **Evidence:** `tools/ruff_stdin.py` checks default paths `["src", "tests", "tools"]` (`0` problems across 67 files), whereas `.github/workflows/ci.yml` invokes `ruff check .` across the entire repo including `experiments/scripts/m6..m8`.
- **Root cause:** `pyproject.toml:48` excluded `experiments/scripts/m2` from ruff, not `m6..m8`, while M6–M8 scripts were written using `tools/ruff_stdin.py` defaults and then frozen under `m8-freeze`.
- **Impact:** Running GitHub Actions CI (`ruff check .`) would fail on lint until either `pyproject.toml` excludes frozen experiment scripts (matching `m2`) or a post-M8 non-protocol formatting commit is approved.
- **Recommended correction:** Do *not* modify frozen M8 scripts without explicit approval; before enabling CI on a pushed branch, request human approval to add `experiments/scripts/m6`, `m7`, `m8` to `extend-exclude` in `pyproject.toml` (same rationale as `m2` at `pyproject.toml:46-48`).
- **Acceptance criteria:** `ruff check .` exits `0` without altering any frozen protocol code.
- **Status:** Open (Requires human approval to adjust `pyproject.toml` exclude list or push).

### AUD-004 — Remote CI Workflows Unverified
- **Severity:** Low (Operational)
- **File and line:** `.github/workflows/ci.yml`, `.github/workflows/security.yml`
- **Evidence:** `docs/milestones/blockers.md` (`BLK-003`); no push to remote has been performed without human approval.
- **Root cause:** Git workflow rule (§12) prohibits pushing without explicit approval.
- **Impact:** Local verification passed (`pytest`, `mypy`, `ruff_stdin.py`, `mutation_check.py`), but remote runner behavior (Python 3.12 matrix + `ruff check .`) is unverified.
- **Recommended correction:** Push `feat/m8-banking-qwen35` after human approval (and after resolving AUD-003).
- **Acceptance criteria:** GitHub Actions green on Python 3.12 and 3.13/3.14.
- **Status:** Open (`BLK-003`).

### AUD-005 — Data Checkpoint Commit `f79fa70` Present on Local `main`
- **Severity:** Low (Git Hygiene)
- **File and line:** Git ref `refs/heads/main` (`f79fa70675a6ba810034a20e20284e56f8a2c54f`)
- **Evidence:** `git log --all --graph --oneline` shows `main` 1 commit ahead of `origin/main` (`f49788c`), containing `results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl`, because `HEAD` was switched to `main` externally during the 3-hour M8 run before checkpoint commit; `feat/m8-banking-qwen35` was then fast-forwarded to include it.
- **Root cause:** External branch switch while unattended M8 run was active.
- **Impact:** No data loss and no impact on `m8-freeze` integrity (`SRC_PATHS` unchanged); merely leaves local `main` ahead of `origin/main` by 1 data commit.
- **Recommended correction:** Upon human approval, run `git branch -f main f49788c` (or keep if merging `feat/m8-banking-qwen35`).
- **Acceptance criteria:** Local `main` aligns with `origin/main` or approved merge target.
- **Status:** Open (Awaiting human approval per §12 non-destructive Git rule).

### AUD-006 — Mutation Testing Scope Excludes AgentDojo Adapter
- **Severity:** Low (Test Depth)
- **File and line:** `tools/mutation_check.py`, `src/agentguard/benchmarks/agentdojo_banking.py`
- **Evidence:** `tools/mutation_check.py` executes 42 mutations across core `src/agentguard/` (`42/42` killed), but runs in `.venv` where `agentdojo` is absent, so `benchmarks/agentdojo_banking.py` is verified by `89` unit/integration tests in `.venv-bench` rather than mutation testing.
- **Root cause:** Environment isolation (`D-010`).
- **Impact:** Core gateway/policy/sandbox invariants are mutation-tested; adapter wiring relies on functional + bypass tests in `tests/bench_agentdojo/`.
- **Recommended correction:** Add adapter-specific mutations in a `.venv-bench` runner if the project expands to more suites.
- **Acceptance criteria:** Adapter enforcement mutations (e.g. removing `consume()` in `GatedToolRunner`) fail `tests/bench_agentdojo/`.
- **Status:** Accepted for v3.1 prototype.

---

## 4. Confirmed Security Invariant Verification Summary

Every invariant `SEC-001` through `SEC-015` remains verified with both positive and negative tests and mutation coverage (`M01`–`M42` all killed, 0 survived). No test was weakened or skipped in the core suite. The state oracle (`src/agentguard/evaluation/oracle.py`) and AgentDojo state predicates remain completely independent of `defense/` and `policy/` (AST import boundary verified by `tests/security/test_boundaries.py`).
