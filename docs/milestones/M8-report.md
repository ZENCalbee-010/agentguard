# M8 — Main Experiment and Statistical Analysis (Narrower Banking Study)

Date: 2026-11-24 | Branch: `feat/m8-banking-qwen35` | Freeze tag: `m8-freeze` (`a1a105f`)
Status: **PASS** (narrower banking study with `qwen3.5:9b`, per D-020; RQ4 remains out of scope/untested due to single qualified local model).

## 1. Deliverables Produced

- Frozen main experiment raw records: `results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl` (440 records, SHA-256 `8f3b74b8418223c7...`)
- B0 run-to-run noise-floor raw records: `results/raw/m8b-noise-b0/qwen3.5_9b-think-off.jsonl` (110 records, SHA-256 `c0fe9927cb8c2dba...`)
- Validated metrics and exported tables: `results/metrics/m8-banking-qwen35/{summary.json, records.csv, attempts.csv}`
- Noise-floor summary: `results/metrics/m8b-noise-b0/noise_floor.json`
- Full statistical summary, failure analysis, and reproducibility manifest: `docs/research/m8-main-report.md`

## 2. Headline Results

- **Integrity:** `INTEGRITY: OK` (`analyze_main.py --frozen-commit m8-freeze`, exit code 0; 440/440 analysed, 0 missing, 0 dirty, 0 infrastructure failures).
- **Noise floor (M8b):** `0/110` disagreements across `run_status`, `attack_attempted`, `attack_executed`, `task_success`, `trajectory`, and token counts (exact 95% CI `[0.000, 0.033]`).
- **Exposure:** **ADEQUATE** (`32/99` clean B0 attempts across `6/11` user tasks; rule $\ge 10$ attempts in $\ge 4$ tasks).
- **H1 (confirmatory, B2 vs B0 executed ASR):** **SUPPORTED (robust to the cluster sign test and the two-way bootstrap)** — B0 `31/99` (31.3%) vs B2 `2/94` (2.1%), paired diff `+25.5 pp`, exact McNemar $p = 1.19 \times 10^{-7}$, cluster CI `[+0.0909, +0.4468]`, sign test $p = 0.03125$, two-way CI `[+0.0707, +0.4945]`, robust to worst-case unclean bounds (`+24.2 pp`, $p = 1.19 \times 10^{-7}$).
- **H2 (descriptive, P1 vs B2 executed ASR):** **DESCRIPTIVE** — B2 `2/94` vs P1 `0/93` (`+2.1 pp`, McNemar $p = 0.50$, cluster CI `[0.0, 0.0652]`); both B2 escapes were wildcard `send_money` calls in `user_task_0`.
- **H3 (descriptive, P1 vs B0 benign utility):** **DESCRIPTIVE** — `8/9` (`valid_13`) and `6/7` (`strict_11`) in all 4 configs (`0/11` benign denials), exact one-sided 95% lower bound `-0.386` (`valid_13`) / `-0.466` (`strict_11`).
- **Key factorial attribution finding:** `B1` and `P1` produced `110/110` identical trajectories; adding heuristic analyzer v0.1 prevented 2 wildcard attacks ($p = 0.50$) while costing **10 legitimate tasks under attack** vs `B2` (`-13.3 pp` `valid_13`, `-17.5 pp` `strict_11`, $p = 0.00195$, `strict_11` cluster CI `[-0.473, -0.016]`), whereas `B2` preserved `100%` of clean utility under attack (`+0.0 pp` vs B0).
- **Cost:** `2.95 h` main + `0.63 h` noise floor = `3.58 h` local Apple M2 Pro compute; **0 THB** API spend.

## 3. Quality Gates (QG-01..QG-10)

| Gate | Status | Evidence |
|---|---|---|
| QG-01 Requirements satisfied | PASS | Frozen M8 protocol executed end-to-end; M8b noise floor completed; report written |
| QG-02 Relevant tests actually run | PASS | Core pytest `414 + 26` (model_adapter outside sandbox), bench pytest `89 passed`, mypy strict clean (42 files), `tools/ruff_stdin.py` 0 problems (67 files) |
| QG-03 Security invariants satisfied | PASS | Zero changes to `src/` since `m8-freeze`; security tests green |
| QG-04 No tests weakened | PASS | Zero changes to `tests/` |
| QG-05 No frozen research artifact changed | PASS | `git diff m8-freeze HEAD -- src experiments/scripts/m7 experiments/scripts/m8 experiments/configs docs/research/m8-analysis-plan.md` empty; verified by `analyze_main.py --frozen-commit m8-freeze` |
| QG-06 Diff reviewed | PASS | Only raw data, metrics outputs, and documentation files added/updated |
| QG-07 Dependencies & configs documented | PASS | `.venv` and `.venv-bench` created from pinned specs on macOS/Python 3.14.6; platform shift recorded in D-021 and R-33 |
| QG-08 Known risks & limitations reported | PASS | All Plan Section 9 caveats + D-021/R-33 documented in `docs/research/m8-main-report.md` |
| QG-09 No prohibited external side effects | PASS | Local simulated AgentDojo banking sandbox + local Ollama only; 0 THB paid API calls; no push/merge |
| QG-10 Milestone status | **PASS** | Ready for M9 Final Audit and Research Package |
