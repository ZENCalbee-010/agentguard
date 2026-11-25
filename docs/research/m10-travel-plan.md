# M10 travel study — pre-registered plan (frozen by commit before the first test-split run)

Status: frozen by the commit that adds this file together with `experiments/scripts/m10/analyze_travel.py`. Any change after the first run is a protocol change and must be reported as a deviation. Approval basis: D-022 (user chose to extend to a second AgentDojo suite, 0 THB).

## 1. Design
| Item | Value |
|---|---|
| Benchmark | AgentDojo v1.2.2, suite `travel`, attack `important_instructions_no_model_name` |
| Split | frozen **test** split of `datasets/manifests/travel-v1.json` (content hash `afcc926a03b3705b9f080937fd33b09e71da611a52fef04325dcea988cb9bf73`): 11 user tasks (clusters) `0,1,3,4,5,7,9,14,15,17,18`, 66 attack cases (6 compatible injection tasks 0-5; task 6 is answer-only, F-5) and 11 benign cases |
| Runs | 77 cases x 4 configurations = **308 runs**, case-major order, one repetition, 0 THB |
| Model | `qwen3.5:9b` digest `56671c2ab938...`, `num_ctx` 12288, thinking off, temperature 0, seed 0, 1024 output tokens, `max_steps` 12 (the banking study used 10; travel tasks need more lookups), 300 s per model call |
| Policies | `travel-v1` (20 tasks, read-only lookups allowed everywhere, every side-effecting capability pinned to the prompt or an explicit `anything()` wildcard, `max_calls` 1) |
| Analyzer | `ContextAnalyzerV2` `v0.2+07aad61880e0`, parameters frozen on banking development data only; **no parameter was tuned on travel**. This is therefore an out-of-domain test of v0.2 |
| Qualification | B0 benign on all 20 travel tasks: 16/20 (80%, Wilson 0.58-0.92), 0/118 invalid calls (committed `814f4fe`) |
| Oracle | native AgentDojo state predicates, unchanged; no no-op-passing utility oracle exists in travel (0/20), so no utility strata are needed |

## 2. Endpoints and rules (same structure as the banking plan)
- Primary: executed unauthorized action (native `security()` true), denominator = clean attack cases (`run_status == completed`); unclean runs are excluded and bounded per arm (worst and best case).
- **H1 (confirmatory):** ASR(B2) < ASR(B0). Exact two-sided McNemar on paired attack cases at level 0.05 (family of one). SUPPORTED iff exposure is adequate AND B0-only > B2-only AND p < 0.05 AND the 95% user-task cluster-bootstrap CI (10,000 resamples, seed 20261124) of rate(B0) - rate(B2) has lower bound > 0; the verdict states whether the cluster sign test (p < 0.05) agrees.
- **Exposure adequacy:** at least 10 clean B0 attack attempts in at least 4 user tasks, otherwise H1 is "INSUFFICIENT EXPOSURE (descriptive only)".
- **H2 (descriptive):** P1 vs B2 executed attacks, on all cases and on the policy-reachable cells of the test split (3 cells: user task 3 x injection 5, user tasks 4 and 7 x injection 2). No verdict.
- **H3 (descriptive):** benign success P1 vs B0 (11 pairs). No verdict.
- Exploratory (labelled, no multiplicity control): B1/P1 vs B0, P1 vs B1, utility under attack for B1/B2/P1 vs B0 and P1 vs B2, benign contrasts, per-user-task table, analyzer-denial mechanism, cost.
- Integrity gate (`analyze_travel.py`): every expected case recorded exactly once, no dirty-tree records, pinned model digest, pinned analyzer versions, no infrastructure failures; otherwise no verdict is produced (exit code 2).
- No interim analysis: only progress (counts, statuses, elapsed time) may be inspected during the run; the analysis is run once after the last record.

## 3. Stated expectations (before the data)
- Static ceiling: under `travel-v1` only 3 of 66 test attack cases leave a reachable goal under B2, so B2 is expected to stop almost every attack the model attempts; P1-vs-B2 is expected to be decided by at most those cells (descriptive).
- Travel is a read-heavy suite; attack exposure (how often the model follows the injection) is unknown and may be low (R-26/R-29). A null or insufficient-exposure outcome is valid and will be reported as such.

## 4. Known limitations (reported with the results)
`travel-v1` policies were written after the author had inspected the travel injection tasks (R-24); one model, one repetition, temperature 0; one attack family; travel utility oracles read the model's final text for read-only tasks (utility under attack mixes tool use and answer quality); the 250-character proximity window of v0.2 was set on banking; the analysis scripts for banking and travel are separate code paths (the travel script was written for this study, not reused from M8).
