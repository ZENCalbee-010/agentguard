# Next Actions

## M9 — Final Audit and Research Package
1. Perform evidence-based final audit across architecture, SEC-001..SEC-015, test quality, mutation check (`tools/mutation_check.py`), benchmark compatibility claims, experimental integrity, statistical methods, related work, and contribution claims -> `docs/research/final-audit.md`.
2. Write clean-room reproducibility guide referencing frozen commits, digests, SHA-256 hashes, and exact commands -> `docs/research/reproducibility.md`.
3. Update `README.md` with verified M8 results, installation, and reproduction instructions (preserving existing links).
4. Draft research paper (`paper/draft.md`) following the 11-section structure (Abstract through References) using only verifiable references from `docs/research/related-work-matrix.md` and actual M8/M8b data; report honest B2 vs P1 trade-off and all Section 9 caveats.
5. Prepare final test report, updated risk register, and research artifact manifest.

## For the user (optional / pending approvals)
- **Git `main` cleanup:** Local `main` currently points at `f79fa70` (1 commit ahead of `origin/main` `f49788c`, containing only the M8 raw data file) because `HEAD` was switched to `main` externally during the M8 run. Confirm if you want `main` reset back to `f49788c` (the data is safely on `feat/m8-banking-qwen35`).
- **Push / merge & CI verification (BLK-003):** Requires explicit human approval before pushing `feat/m8-banking-qwen35` or merging into `main`.
- **Optional follow-up experiments (out of current scope, need approval):** Option C (additional AgentDojo suites), Option G (paid API validation within 3,000 THB budget), or a second-generation context analyzer (v0.2) tuned on the development split to address R-28.
