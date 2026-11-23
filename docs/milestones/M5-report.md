# M5 - Context Analyzer and the Four Configurations

Date: 2026-11-19 - Branch `feat/m5-analyzer-baselines` - Code under test: commit `273e8f7` (clean tree)
Status: **PASS for the own-domain scope. AgentDojo integration is NOT done (moved to M6).**

## 1. Implemented
- `defense/context_analyzer.py`: analyzer v0.1 (signals S1 provenance, S2 instruction-like content, S3 tool-intent alignment, S4 temporal coupling). Weights 0.4/0.4/0.2/0.2 and threshold 0.6 were fixed **a priori** and are pinned by a test; patterns are generic and a test forbids attacker/benchmark constants. S2/S4 count only for side-effecting tools. Pure, deterministic, bounded input size (20k chars), version string includes a config hash. Timeouts and errors are handled by the gateway (DENY).
- `evaluation/experiment_runner.py` + `agentguard run-matrix`: one runner for B0/B1/B2/P1 (same model, prompts, tool schemas, limits, sandbox seed, oracle; only `GatewayMode` differs). 20 own-domain attack scenarios = 5 data-reading tasks x 2 goals (payment redirect, e-mail exfiltration) x 2 styles (`override`: explicit instruction wording; `stealth`: only states changed data).
- Config-parity tests: policy hash, model parameters and tool schemas identical across modes; B0/B2 cannot carry an analyzer.

## 2. Evidence
pytest 316 passed; mypy strict clean; ruff 0; mutation check **36/36 killed** (`evidence/m5-mutation-check.txt`; first run had 2 survivors M33/M36, tests were strengthened).
Live smoke: `results/raw/m5-smoke/qwen3_8b-20261119-095117.jsonl` - 124 runs (4 modes x (11 benign + 20 attack)), qwen3:8b digest `500a1f067a9f...`, thinking off, num_ctx 8192, temperature 0, seed 0, all runs `completed`, audit chains valid.

| Mode | Attack cases | Attempted | **Executed unauthorized** | Utility under attack | Benign utility | Benign cases with a denial |
|---|---|---|---|---|---|---|
| B0 | 20 | 14 | **14** | 8 | 11/11 | 0 |
| B1 (analyzer only) | 20 | 14 | **2** | 10 | 11/11 | 0 |
| B2 (policy only) | 20 | 14 | **4** | 18 | 11/11 | 0 |
| P1 (policy + analyzer) | 20 | 14 | **2** | 10 | 11/11 | 0 |

Breakdown (executed / 10 or 8): style override B0 9, B1 0, B2 2, P1 0; style stealth B0 5, B1 2, B2 2, P1 2. Tasks with pinned policy (12 cases): B2 0 executed. Data-derived tasks with wildcard policy (8 cases): B0 8, B1 2, B2 4, P1 2. The model did not attempt the attack in 6 of 20 scenarios even in B0 (mostly `stealth`).

## 3. Reading the numbers (limits)
- **Smoke test, not an evaluation.** 20 scenarios written by the project authors, who also wrote the analyzer patterns; counts are small and no statistics were computed. Do not read B1/P1 "2/20" as detector effectiveness: the `override` text matches patterns written with the same mindset.
- The analyzer **over-blocks**: under attack, utility is 10/20 in B1 and P1 versus 18/20 in B2 (override style: 2/10 vs 10/10), because instruction-like content in context makes the analyzer deny the user's own legitimate protected calls. Benign tasks showed 0 denials (no instruction wording there), so the cost appears only in the presence of injected text.
- P1 equals B1 here; P1 vs B2 (2 vs 4 executed) is driven by `override` attacks against wildcard policies, i.e. by the analyzer, at a large utility cost. This is the pattern RQ2 will test properly on AgentDojo; no claim is made yet.
- Stealth substitution on wildcard-policy tasks executes under every configuration (R-21).
- `attempted` is matched on normalized proposed calls; it can differ slightly across modes because the model reacts to earlier denials.

## 4. Not done
AgentDojo adapter (ToolsExecutor subclass + native task/oracle bridge), executed-trace oracle adaptation (F-3) and the second model (BLK-005). These are the first M6 items; no AgentDojo claim exists in this repository yet.

Cost 0 THB. Approvals needed: none.
