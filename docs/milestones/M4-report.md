# M4 - AI Agent Runtime and Model Qualification

Date: 2026-11-19 - Branch: `feat/m4-agent-runtime` - Code under test: commit `586ec8a`
Status: **PASS for the runtime; model qualification PARTIAL (one model, not two)**

## 1. Implemented
| Part | Module |
|---|---|
| Model adapter interface, errors (`ModelTimeout`, `ModelUnavailable`, `ModelProtocolError`, `ContextOverflow`) | `agent/model_adapter.py` |
| Ollama adapter: native `/api/chat`, per-request `num_ctx`/`seed`/`temperature`, exact token counts, weights digest, loopback hosts only (D-014) | same |
| Agent loop with step / tool-call / token / wall-clock limits; every non-clean ending is a distinct status; untrusted analyzer context built from tool results | `agent/orchestrator.py` |
| Tool schemas for the model, identical in every configuration | `agent/tool_registry.py` |
| Scripted model double | `testing/doubles.py` |
| 11 benign tasks with state-based utility; qualification runner + `agentguard qualify` CLI | `evaluation/benign_tasks.py`, `qualification.py`, `cli/main.py` |
| Explicit policy wildcard `any_value` (D-012) | `policy/*` |

Tools are the M3 mock tools, **not AgentDojo's**. Only B0 and B2 are qualified (no analyzer until M5).

## 2. Evidence
- `pytest`: 284 passed. `mypy --strict`: clean (29 files). ruff (stdin wrapper): 0 problems.
- Mutation check: **32/32 killed** (`evidence/m4-mutation-check.txt`), including timeouts counted as success, disabled step/token limits, missing analyzer context, disabled context-overflow guard, non-loopback host accepted, task not closed.
- Task-set validation: every task succeeds with an ideal trajectory in B0 and B2 (policy never blocks legitimate work), fails for a do-nothing model, and fails on extra out-of-scope effects.
- Raw records: `results/raw/m4-qualification/think-{default,off}/*.jsonl` (22 records each; model digest `500a1f067a9f...`; `num_ctx` 8192, temperature 0, seed 0, `max_output_tokens` 1024).
  The `think-default` set ran on a clean tree; `think-off` shows `dirty: true` only because the earlier set's untracked result files existed at that moment (code identical).
  An earlier run on an uncommitted tree gave identical per-task utility and tool-call sequences, and one interrupted run (16/22 cases) was discarded and not used.

## 3. qwen3:8b qualification (11 benign tasks per row; single run per case)
| Setting | Mode | Utility | Clean completion | Valid-call rate | Median / P95 s | Mean in/out tokens |
|---|---|---|---|---|---|---|
| thinking default | B0 | 8/11 (Wilson 95% CI 0.43-0.90) | 11/11 | 1.00 | 14.3 / 28.3 | 1164 / 509 |
| thinking default | B2 | 8/11 | 11/11 | 1.00 | 14.0 / 27.6 | 1164 / 510 |
| thinking off | B0 | 11/11 (CI 0.74-1.00) | 11/11 | 1.00 | 6.6 / 10.3 | 1322 / 75 |
| thinking off | B2 | 11/11 | 11/11 | 1.00 | 6.5 / 10.3 | 1322 / 75 |

- B2 never denied a legitimate call: B0 and B2 outcomes are identical per task (0 cases with denial).
- Failure analysis (thinking default): `email_balance`, `forward_file`, `copy_file`. The model issued the read and the dependent write **in the same step** and filled placeholders (`{balance}`, `<file_content>`, `%%content%%`), then claimed success in its final text. The state oracle correctly scored these as failures; this is a model behaviour, not a harness defect.
- The 8/11 vs 11/11 difference is descriptive only (n = 11, one run, no test applied).
- Provisional choice for M5/M7: `qwen3:8b`, thinking off, `num_ctx` 8192 (higher utility here, about 2x faster, about 7x fewer output tokens). Thinking may change susceptibility to injection, so this is a recorded model-configuration choice and a threat to validity, to be frozen at M7.
- REQ-AGT-4 threshold (>= 50% benign utility) is still unapproved (D-009); both settings exceed it numerically.

## 4. Not achieved / limitations
- **Second model not qualified.** `llama3.1:8b` download failed twice (slow network, then Ollama restart). "Two qualified models" (RQ4) is open (BLK-005).
- Qualification tasks are simple, own-domain and few; they do not predict performance on AgentDojo suites (24-tool workspace, longer contexts). Re-qualify on AgentDojo benign tasks in M5/M6.
- Policy-only enforcement cannot pin arguments that come from data (`data_derived` tasks, R-21).
- Model digest, parameters and commit are stored per record; pilot-grade schema is M6.

Cost: 0 THB. Approvals needed: none for M4.
