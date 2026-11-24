# Reproducibility Guide and Research Artifact Manifest — AgentGuard v3.1

This document provides clean-room instructions to verify tests, recompute every reported metric from raw experiment logs, and re-run the frozen M8 / M8b experiments locally without paid API usage.

## 1. Frozen Provenance & Environment Summary

| Component | Exact Value |
|---|---|
| Freeze tag / commit | `m8-freeze` → `a1a105f25d56ef1244887cf901091c4f4ab811a3` |
| Feature branch | `feat/m8-banking-qwen35` |
| Python declared target | `>=3.12` (M0–M7d developed on Windows 11 / Python 3.13.14; M8/M8b executed on macOS arm64 Apple M2 Pro 16 GiB / Python 3.14.6, see D-021 / R-33) |
| Core dependency lock | `requirements-lock.txt` (`pydantic==2.14.3`, `PyYAML==6.0.3`, `pytest==9.2.0`, `ruff==0.17.5`, `mypy==2.4.1`) |
| Benchmark dependency freeze | `docs/research/evidence/m2-bench-env-freeze.txt` (`agentdojo==0.1.35`, suite `v1.2.2`, MIT) |
| Local model | Ollama `qwen3.5:9b`, pinned digest `56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90` |
| Generation parameters | `num_ctx=12288`, `think=false`, `temperature=0.0`, `seed=0`, `max_output_tokens=1024`, `max_steps=10`, `max_wall_s=300` |
| Policy set | `banking-v2` (SHA-256 `086eaa0107dd639737c801ea42b7200121e6cc36a8822fab1eea736fefa86f4e`) |
| Context analyzer | `v0.1+54a3f7c1d1a3` (parameters fixed a priori in M5; `threshold=0.6`, `w_provenance=0.4`, `w_instruction=0.4`, `w_alignment=0.2`, `w_temporal=0.2`) |
| Dataset manifest | `datasets/manifests/banking-v1.json` (SHA-256 `9db39933c140a2555937fa72b840dc8e584b88eef78d7ff14d8cd43bc389e153`) |
| Analysis RNG seed | `20261119` (`10,000` bootstrap resamples, pre-registered in `experiments/scripts/m8/analyze_main.py`) |

## 2. Clean-Room Installation

Two isolated virtual environments are used (Decision D-010) so AgentDojo's 70+ transitive packages never pollute the pinned core environment.

### 2.1 Core Environment (`.venv`) — No LLM or Benchmark Needed

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/agentguard version
```

Verify core tests, static typing, lint, and security-core mutation suite:

```bash
.venv/bin/python -m pytest -q
.venv/bin/mypy
.venv/bin/python tools/ruff_stdin.py
.venv/bin/python tools/mutation_check.py
```

*(Note: `tests/unit/test_model_adapter.py::test_unresponsive_server_raises_model_timeout` binds a local loopback socket and requires localhost socket permission. On Windows where native `ruff.exe` hits BLK-001, `tools/ruff_stdin.py` checks `src/`, `tests/`, and `tools/`.)*

### 2.2 Benchmark Environment (`.venv-bench`) — Required Only for AgentDojo Adapter & Live Runs

```bash
python3 -m venv .venv-bench
.venv-bench/bin/python -m pip install -r docs/research/evidence/m2-bench-env-freeze.txt -e . pytest==9.2.0
.venv-bench/bin/python -m pytest tests/bench_agentdojo -q
```

## 3. Recomputing All M8 & M8b Metrics from Stored Raw Evidence (No LLM Required)

Every number in `docs/research/m8-main-report.md` and `paper/draft.md` is deterministically recomputable from the committed JSONL files in ~5 seconds:

```bash
# Recompute main experiment metrics, verdicts, sensitivity bounds, and CSVs
.venv/bin/python experiments/scripts/m8/analyze_main.py \
  --config experiments/configs/m8-banking-qwen35.yaml \
  --records results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl \
  --out /tmp/m8-recompute \
  --frozen-commit m8-freeze

# Recompute M8b B0 noise floor
.venv/bin/python experiments/scripts/m8/noise_floor.py \
  results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl \
  results/raw/m8b-noise-b0/qwen3.5_9b-think-off.jsonl \
  /tmp/m8-recompute/noise_floor.json

# Verify exact match with committed artifacts
diff -u results/metrics/m8-banking-qwen35/summary.json /tmp/m8-recompute/summary.json
diff -u results/metrics/m8b-noise-b0/noise_floor.json /tmp/m8-recompute/noise_floor.json

# Regenerate SVG figures from validated summary.json
.venv/bin/python experiments/scripts/m9/generate_figures.py \
  --summary results/metrics/m8-banking-qwen35/summary.json \
  --out /tmp/m8-recompute/figures
```

## 4. Re-Running M8 & M8b Live Against Local Ollama

Requirements: local Ollama daemon running at `http://127.0.0.1:11434`, clean Git working tree, `qwen3.5:9b` pulled with digest prefix `56671c2ab938`.

```bash
ollama pull qwen3.5:9b
ollama list   # verify ID starts with 56671c2ab938

# 1. Main experiment (440 runs; ~3 h on Apple M2 Pro 16 GiB, ~6 h on 8 GiB GPU; 0 THB)
.venv-bench/bin/python experiments/scripts/m8/run_main.py \
  --config experiments/configs/m8-banking-qwen35.yaml \
  --out results/raw/m8-repro/main.jsonl

# 2. B0 noise-floor repeat (110 runs; ~38 min on Apple M2 Pro; 0 THB)
.venv-bench/bin/python experiments/scripts/m8/run_main.py \
  --config experiments/configs/m8b-noise-b0.yaml \
  --out results/raw/m8-repro/noise-b0.jsonl
```

**Expected reproducibility caveats:**
- On the same hardware/backend (Apple M2 Pro Metal), M8b exhibited `0/110` outcome, trajectory, and token differences (`exact 95% CI [0.000, 0.033]`).
- Across different GPU backends (e.g. AMD ROCm/Vulkan on Windows vs Apple Metal on macOS), floating-point tie-breaking at `temperature=0.0` can shift individual trajectories (observed between M7c qualification on Windows and M8 on macOS, D-021 / R-33).

## 5. Research Artifact Manifest

| Artifact | Purpose | Path | SHA-256 |
|---|---|---|---|
| Frozen manifest | Banking cluster split (dev/val/test) | `datasets/manifests/banking-v1.json` | `9db39933c140a2555937fa72b840dc8e584b88eef78d7ff14d8cd43bc389e153` |
| M8 config | Frozen main study config (440 runs) | `experiments/configs/m8-banking-qwen35.yaml` | config hash `34256f9a9634` |
| M8b config | Frozen B0 noise-floor config (110 runs) | `experiments/configs/m8b-noise-b0.yaml` | config hash `e822bdad3df5` |
| Pre-registration | Frozen M8 analysis plan | `docs/research/m8-analysis-plan.md` | frozen at tag `m8-freeze` (`a1a105f`) |
| Static ceiling evidence | Ground-truth replay matrix (`banking-v2`) | `docs/research/evidence/m7b-policy-coverage-matrix-v2.json` | verified by `analyze_main.py` |
| H3 operating characteristics | Exact Berger-Boos Type I error & power | `docs/research/evidence/m8-h3-operating-characteristics.json` | produced by `experiments/scripts/m8/h3_operating_characteristics.py` |
| Main raw data | 440 formal `ExperimentRecord` JSONL lines | `results/raw/m8-banking-qwen35/qwen3.5_9b-think-off.jsonl` | `8f3b74b8418223c7c9cd7bc9f38e9e4472c804e5eb3db12742c99ce9737a56a2` |
| Noise-floor raw data | 110 B0 repeat `ExperimentRecord` JSONL lines | `results/raw/m8b-noise-b0/qwen3.5_9b-think-off.jsonl` | `c0fe9927cb8c2dbaba13c6cc7a9e915725df1f572277f9173a40cd908d3b2aef` |
| Main metrics summary | Pre-registered verdicts & contrasts | `results/metrics/m8-banking-qwen35/summary.json` | `166eeafc600c0d54a3dac007db126e0089460bf4bae4b5b6fce1b5ac9fafe2bd` |
| Noise-floor summary | Run-to-run agreement statistics | `results/metrics/m8b-noise-b0/noise_floor.json` | `47b58199ddc5ef95a40eeca7c5c575c4de9771e2fbef08c9140e2e6a2474c0db` |
| Main report | Detailed statistical & failure analysis | `docs/research/m8-main-report.md` | — |
| Final audit | Evidence-based audit (architecture, invariants, integrity) | `docs/research/final-audit.md` | — |
| Draft paper | 11-section research paper draft | `paper/draft.md` | — |
| Publication figures | 3 SVG charts generated from `summary.json` | `results/figures/fig{1,2,3}_*.svg` | `experiments/scripts/m9/generate_figures.py` |
