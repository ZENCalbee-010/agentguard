# Experiment Budget (M7, measured from the pilot)

Source: `results/metrics/pilot-summary/summary.json` (120 runs, qwen3:8b, thinking off, local GPU). Money spent so far: **0 THB** (local inference). Project cap: 3,000 THB, no paid API use without explicit approval (REQ-GOV-1). No API pricing was looked up or assumed in this document.

## Measured cost per run (wall clock, local RX 7600 8 GiB)
| Config | Mean s/run | Median s | Max s | Mean input tok | Mean output tok | Mean model calls |
|---|---|---|---|---|---|---|
| B0 | 22.5 | 20.4 | 52.7 | 7,675 | 262 | 5.6 |
| B1 | 22.8 | 28.2 | 40.5 | 7,749 | 271 | 5.6 |
| B2 | 17.3 | 18.1 | 44.9 | 5,856 | 198 | 4.5 |
| P1 | 17.3 | 18.1 | 45.0 | 5,856 | 198 | 4.5 |

Overall 20.0 s/run, 39.9 min for 120 runs. B2/P1 are cheaper only because denials end trajectories earlier (fewer model calls), not because the defense is free. The analyzer's own decision time was not measured separately (it is pure Python and small relative to a model call). Peak memory was not measured. Context used per run stayed under the 12,288-token window (no overflow).

## Projection for the banking study (local, 0 THB)
| Scope | Cases | Runs (x4 configs) | Time at 20 s/run |
|---|---|---|---|
| Test split only | 110 (99 attack + 11 benign) | 440 | about 2.4 h per repetition |
| All splits | 160 | 640 | about 3.6 h per repetition |
| All splits, 3 repetitions at temperature > 0 | 480 | 1,920 | about 10.7 h |

At temperature 0 and a fixed seed the pilot trajectories were reproducible in M4, so repetitions only add information if sampling is enabled. Token volume for one all-splits pass (640 runs at the measured per-run means) is about 4.3 M input and 0.15 M output tokens (relevant only if an external paid model is ever approved; its price must be verified first).

## What limits the study is not compute
- **Exposure:** the model attempted the attack in 10 of 26 B0 clean cases (38%); attack cases without exposure carry no information about a defense.
- **Discordant pairs:** an exact McNemar test at alpha = 0.05 (two-sided) needs at least 6 discordant pairs all in one direction (6/0 gives p = 0.031; 5/0 gives 0.0625). For P1 vs B2 on banking, only user tasks 0 and 10 (test split) have policies that leave a reachable goal (12 of 18 pairs by the static matrix) and the attempt rate is about 38%, so about 4-5 events are expected: P1 vs B2 cannot reach significance on banking, and with 2 clusters the cluster bootstrap is not meaningful either.
- **Clusters:** the unit of analysis is the user task. 11 test clusters support B0-vs-B2 style contrasts only if the effect is large and consistent.

## Sample-size statement
Main-study sizes are **not** justified by this pilot beyond the following: banking test split (11 clusters, 99 attack cases) is affordable and can support RQ1, RQ3 and RQ5 descriptively; RQ2 requires a suite with many data-derived arguments (workspace, travel) or a different design, and RQ4 requires a second qualified model (not available, BLK-005). No power calculation was done for effects the pilot cannot estimate.

## Budget status
Spent 0 THB; projected main banking study 0 THB; optional external-validation API use not proposed, would require approval and verified pricing.


---
## Addendum (qwen3.5:9b, thinking off, measured in `m7c`)
| Config | Mean s/run |
|---|---|
| all four, 120 runs | 50.1 (100.2 min total); mean input 9,637 and output 586 tokens per run |

Projection with qwen3.5:9b (local, 0 THB): banking test split 440 runs about 6.1 h per repetition; all splits 640 runs about 8.9 h per repetition. The 8B model was about 2.4x faster, but is not adequately qualified. Peak memory: 5.9 GB VRAM at `num_ctx` 12288 (from `ollama ps`).
