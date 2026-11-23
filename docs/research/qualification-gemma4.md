# M7d - second model for RQ4: gemma4:e4b qualification (not qualified)

Date: 2026-11-19. Branch `feat/m7d-gemma4-qualification`. Qualification only (B0, benign, 16 banking user tasks); no defense configuration was run, so nothing here can tune a defense.

## Model choice (verified)
The Ollama library tags page lists `gemma4:e4b-it-q4_K_M` at 6.6 GB (the default `gemma4:e4b` tag is shown as a 6.6-9.5 GB range, so the explicit Q4_K_M tag was used). `ollama show` on the pulled model reports: Q4_K_M, 7.5B parameters, capabilities completion / vision / audio / tools / thinking, digest `dc35e8d9c606`. Loaded at `num_ctx` 12288 it ran 100% on GPU. `lfm2.5` was not tried.

## Results (`results/metrics/qualification-summary/`)
| Model | Setting | all 16 | 13 valid | 11 strict | invalid-call rate | runs with no tool call | median s/run |
|---|---|---|---|---|---|---|---|
| qwen3:8b | think off | 8/16 | 5/13 (0.18-0.64) | 4/11 | 0.029 | 3/16 | 12.1 |
| llama3.1:8b | - | 5/16 | 2/13 (0.04-0.42) | 1/11 | 0.065 | 0/16 | - |
| qwen3.5:9b | think off | 12/16 | 9/13 (0.42-0.87) | 7/11 | 0.0 | 2/16 | 30.4 |
| **gemma4:e4b Q4_K_M** | think off | 8/16 (0.28-0.72) | **5/13 (0.18-0.64)** | 3/11 (0.10-0.57) | 0.0 (14 calls) | **7/16** | 5.9 |
| **gemma4:e4b Q4_K_M** | thinking on (model default) | 8/16 (0.28-0.72) | **5/13 (0.18-0.64)** | 3/11 (0.10-0.57) | 0.0 (14 calls) | **6/16** | 13.0 |

## Reading
1. gemma4:e4b does **not** reach the provisional 50% gate on the 13 valid tasks in either thinking setting (5/13; the interval reaches 0.64 but the point estimate is 38%). The thinking setting does not explain the gap.
2. It often does not act: 6-7 of 16 runs made no tool call. Most of its passes are tasks that a do-nothing agent also passes (F-6 tasks 5, 6, 8; inaction tasks 9, 10), so the 5/13 is, if anything, optimistic. On the strict 11 it passes 3.
3. It emits no malformed calls (0 of 14), so the failure is task completion, not tool-format compliance.
4. Consequence: **RQ4 still has one qualified model (qwen3.5:9b).** The comparison "consistency across model families" is not testable with the local models tried so far (qwen3:8b, llama3.1:8b, qwen3.5:9b, gemma4:e4b).

## Provenance notes
- Think-off records: code commit `d3c489c`, `code_dirty = false`.
- Thinking-on records: same commit, `code_dirty = true`. The only differences from the commit were the untracked output files of the preceding run (`git status` showed nothing else). No source file was modified.
- `qualification_summary.py` overwrites its output file with only the models passed to it. The first invocation on the thinking-on file alone replaced the combined summary; it was restored from git and regenerated, and the thinking-on result is kept in `banking_b0_benign_gemma4_think.json` because both settings share one model id and would otherwise collide.
- One repetition, temperature 0, seed 0, one run per task. Intervals are wide (n = 13).
