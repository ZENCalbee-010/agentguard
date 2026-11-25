# Next Actions

All milestones (**M0–M9**) and all three user-approved post-M9 follow-up tracks (**M10 / D-022**: remote CI verification, `ContextAnalyzer v0.2`, and cross-suite AgentDojo `travel` evaluation) are **PASS / COMPLETE** with **0 THB** API spend (`0 / 3,000 THB`).

## Optional Pending Human Decisions (No Action Taken Without Approval)
1. **Merge to `main`:** Review and merge `feat/m10-v02-and-travel` (which includes `feat/m8-banking-qwen35`) into `main` via GitHub Pull Request after verifying green CI on `feat/m10-v02-and-travel`.
2. **External Model Validation (RQ4 — Optional, within 3,000 THB budget):** Run a second qualified model (either a newly pulled ~14B+ local model or an explicitly approved low-cost API model) on banking and/or travel test splits to test cross-model consistency.
3. **Full-text Related-Work Check Before External Submission:** Verify abstract-only cells for DRIFT, IGTA, Progent, and LlamaFirewall against full PDFs before submitting `paper/draft.md`.
