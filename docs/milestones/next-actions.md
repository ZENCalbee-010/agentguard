# Next Actions

All planned milestones (**M0–M9**) for the approved narrower banking study (`qwen3.5:9b`, AgentDojo banking v1.2.2) are **PASS / COMPLETE** on branch `feat/m8-banking-qwen35`.

## Pending Human Decisions (No Action Taken Without Approval)
1. **Git `main` cleanup (`AUD-005` / `D-021`):** Confirm whether to reset local `main` from `f79fa70` back to `origin/main` (`f49788c`) before merging or pushing.
2. **CI lint scope (`AUD-003`):** Approve adding `experiments/scripts/m6`, `m7`, `m8` to `extend-exclude` in `pyproject.toml` (matching `m2`) so GitHub Actions `ruff check .` passes without touching frozen protocol scripts.
3. **Push / merge & remote CI (`BLK-003` / `AUD-004`):** Approve pushing `feat/m8-banking-qwen35` (and optionally tag `m8-freeze`) to remote to verify `.github/workflows/{ci,security}.yml`.
4. **Full-text related-work check before external paper submission:** Verify abstract-only matrix cells for DRIFT, IGTA, Progent, and LlamaFirewall against full PDFs before submitting `paper/draft.md`.

## Optional Future Research Extensions (Out of Current Frozen Scope)
- **Analyzer v0.2 (`AUD-001` / `R-28`):** Design and tune an argument-scoped provenance detector on the development split only (restricting `ANALYZER_DENY` to wildcard/tainted parameters) to eliminate the `-13.3` to `-17.5 pp` attack-time utility loss.
- **Cross-model & cross-suite generalization (`RQ4` / `R-30`):** Evaluate additional qualified local models or an approved paid API model (within the 3,000 THB budget, currently 0 THB spent) and adapt AgentDojo `workspace`, `travel`, and `slack` suites.
