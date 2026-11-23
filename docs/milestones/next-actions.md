# Next Actions

## M8 (narrower banking study, qwen3.5:9b), in order
1. Tag the freeze commit (`git tag m8-freeze`) and record its SHA in `docs/milestones/status.md`.
2. Run `experiments/scripts/m8/run_main.py` (about 6 h, 0 THB) from `.venv-bench` with `--config experiments/configs/m8-banking-qwen35.yaml --out results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl`. No interim analysis of outcomes; if interrupted, commit the partial raw file and run the same command again.
3. Run the B0 noise-floor run (`experiments/configs/m8b-noise-b0.yaml`, about 1.5 h) and `experiments/scripts/m8/noise_floor.py`.
4. Run `experiments/scripts/m8/analyze_main.py --frozen-commit m8-freeze` once, after the last record.
5. Report in Thai (section 14 format) with the pre-registered verdicts, the limitations of `docs/research/m8-analysis-plan.md` section 9, and the paper-relevant caveats.

## For the user
- **Correct D-020 if the agent misread your choice:** it treats "the narrower banking study with qwen3.5:9b" as approval of delta = 10 pp, the 50% gate on the 13 valid tasks and thinking = off.
- Still not approved and out of scope here: option C (more suites), G (paid API validation), F (F-4 sensitivity), any oracle or policy change, push/merge (BLK-003).
