# M3 — Security Core and Minimal Vertical Slice

Date: 2026-11-18 · Branch: `feat/m3-security-core` · Status: **PASS** (with the limitations in §6)
No LLM is used anywhere in this milestone.

## 1. What exists

| Component | Module | Notes |
|---|---|---|
| Trusted task context, policy schema, decisions | `policy/schemas.py` | Frozen pydantic models; `Decision` carries an HMAC bound to (decision id, task id, call hash, verdict) |
| Capability store + trusted channel | `policy/capability_store.py` | Policy constants are normalized with the same normalizers as call arguments; malformed policy fails closed (`PolicyError`) |
| Tool registry | `agent/tool_registry.py` | Name/argument validation, normalization, `protected` flag, security-relevant parameters |
| Policy engine | `policy/policy_engine.py` | Pure; deny-by-default; explicit deny wins; allow must constrain every security-relevant argument; per-capability call budget. Takes **no** untrusted context |
| Authorization gateway | `defense/authorization_gateway.py` | B0/B1/B2/P1 semantics exactly as in `docs/spec/architecture.md` §4; analyzer interface + timeout; every failure path denies |
| Sandbox state, mock tools, executor | `sandbox/*` | In-memory only; atomic commit; executor needs a valid single-use ALLOW decision for exactly that call |
| Audit logger | `storage/audit_logger.py` | SQLite, hash-chained, tamper-evident |
| Oracle | `evaluation/oracle.py` | State-only goals + attempt matcher; independent of defense code (AST-enforced) |
| Composition root | `stack.py` | One builder for all four configurations (configs differ only in `GatewayMode`) |
| Test doubles / builders | `testing/*` | Deterministic analyzers; compact policy builders |

Tools in this slice are our own simulated `read_file`, `get_balance`, `send_money`, `send_email`,
`write_file`, `delete_file`. **They are not AgentDojo's tools**; the AgentDojo adapter
(`ToolsExecutor` subclass calling this gateway) is M5/M6 work and is not validated here.

## 2. Reason-code taxonomy (clarification D-011)

`security-invariants.md` uses `NO_CAPABILITY` (SEC-001) and `NO_MATCHING_RULE` (SEC-005) without
defining the difference. Implemented meaning (no change to any invariant): `NO_CAPABILITY` = the policy
holds no allow-capability for the tool at all (including the empty policy); `NO_MATCHING_RULE` = an
allow-capability for the tool exists but the call is outside its constraints or leaves a
security-relevant argument unconstrained.

## 3. Invariant → test traceability (all pass)

| Invariant | Positive | Negative |
|---|---|---|
| SEC-001 | `test_t001_p_allowed_call_in_scope` | `test_t001_n_untrusted_text_cannot_grant_capabilities` (B2, P1) |
| SEC-002 | `test_t002_p_allow_decision_applies_effect` | `test_t002_n_executor_refuses_without_valid_decision`, `test_t002_n_denied_decision_cannot_be_executed_and_allow_is_single_use` |
| SEC-003 | `test_t003_p_allowed_write_changes_state` | `test_t003_n_denied_call_leaves_no_side_effect` (B1, B2, P1), `test_t003_n_failed_allowed_call_is_atomic`, property test `test_ac_m3_16_*` (600 random calls × B2/P1) |
| SEC-004 | `test_t004_p_valid_call_passes_validation` | `test_t004_n_invalid_calls_never_execute_in_any_config` (13 inputs × B0/B2), `test_t004_n_wrong_recipient_and_out_of_scope_path` |
| SEC-005 | `test_t005_p_explicit_allow` | `test_t005_n_default_deny` |
| SEC-006 | `test_t006_p_p1_allows_when_both_allow` | `test_t006_n_analyzer_cannot_override_policy_denial` (analyzer call count 0), `test_t006_n_analyzer_can_restrict_a_policy_allow` |
| SEC-007 | `test_t007_p_call_uses_its_own_tasks_scope` | `test_t007_n_scope_and_decisions_do_not_cross_tasks`, `test_t007_n_closed_task_scope_cannot_be_used` |
| SEC-008 | `test_t008_p_grant_through_trusted_channel` | `test_t008_n_forged_or_misbound_tokens_are_rejected`, `test_t008_n_task_lifecycle_needs_the_trusted_channel` |
| SEC-009 | `test_t009_p_untrusted_text_reaches_the_analyzer_as_data` | `test_t009_n_untrusted_items_never_reach_policy_evaluation`, `test_t009_n_context_items_cannot_claim_trust_and_tool_output_is_untrusted` |
| SEC-010 | `test_t010_p_every_decision_is_recorded` | `test_t010_n_denials_invalid_calls_and_errors_are_recorded_and_tamper_evident`, `test_t010_n_audit_failure_prevents_execution` |
| SEC-011 | `test_t011_p_equivalent_spellings_resolve_to_the_allowed_resource` | `test_t011_n_traversal_and_lookalike_paths_denied` (7 paths), `test_t011_n_recipient_spelling_tricks_denied`, normalization boundary tests |
| SEC-012 | `test_t012_p_legitimate_multistep_task_completes` | `test_t012_n_substitution_and_chained_exfiltration_denied_at_offending_step`, `test_t012_n_call_budget_enforced`, `test_t012_n_denied_attempts_do_not_consume_budget` |
| SEC-013 | `test_t013_p_analyzer_within_timeout_decides_normally` | `test_t013_n_analyzer_failure_never_allows` (raise / malformed / timeout × B1, P1), `test_t013_n_policy_engine_failure_never_allows` |
| SEC-014 | `test_t014_p_all_configs_share_policy_engine_registry_and_policy_hash` | `test_t014_n_enforcement_cannot_be_switched_off_by_configuration`, `test_t014_n_records_carry_policy_hash_and_mode` |
| SEC-015 | `test_t015_p_every_run_gets_a_fresh_sandbox` | `test_t015_n_non_mock_backend_and_shared_state_are_refused`, `test_ac_m3_17_sandbox_has_no_network_process_or_file_capabilities` |
| REQ-ORC-1/2/3 | oracle tests in `tests/unit/test_audit_and_oracle.py` (claim without state change is not success) | `test_ac_m3_17_oracle_does_not_import_*` |

## 4. Evidence (this working tree)

| Check | Result | File |
|---|---|---|
| `pytest tests` | **185 passed** (security-marked 94, integration 9, regression 2) | `evidence/m3-pytest-verbose.txt` |
| `mypy` strict, 25 source files | no issues | `evidence/m3-mypy.txt` |
| ruff (via stdin wrapper, BLK-001), 37 files | 0 problems | `evidence/m3-ruff.txt` |
| Mutation check, `tools/mutation_check.py` | **22/22 killed** | `evidence/m3-mutation-check.txt` |

Mutation check: 22 single-line weakenings (deny-wins removed, MAC check removed, analyzer error
allowed, traversal clamped, non-atomic execution, etc.) were each applied and the suite had to
fail. One mutation (M22) initially **survived**; analysis showed the e-mail ASCII check was only
exercised by an input that a later regex already rejected, so the test was strengthened with the
Kelvin sign (which lower-cases to ASCII `k`) and the mutation is now killed.

Not run: native `ruff check .` (BLK-001), CI (no remote), any test of the file-backed audit path.

## 5. Self-review (evidence-based; not an independent audit)

Reviewed against the approved specification by walking through the control flow of each module and trying to construct a bypass.

### Confirmed defects (fixed, regression tests added)
| ID | Severity | Where | Evidence | Root cause | Impact | Fix / test |
|---|---|---|---|---|---|---|
| RF-001 | High | `normalize.py:normalize_amount` (and gateway call-validation path) | Unit test with `"1e400"` raised `decimal.InvalidOperation` out of the normalizer | `Decimal.quantize` overflow not caught; gateway only caught `InvalidCallError` | A hostile amount made the gateway raise instead of returning DENY (crash/DoS in the security path, caller-dependent fail-open risk) | Range check + guarded `quantize`; gateway now maps **any** validation exception to `INVALID_CALL`. `test_rf001_*` |
| RF-002 | Low | `normalize_iban` / `normalize_email` | `ß` in an IBAN was silently rewritten to `SS`; Kelvin sign lower-cased into ASCII `k` | Case mapping applied before an ASCII check | Canonical value was still the one compared and executed (no policy bypass), but look-alikes were accepted as ordinary values | Reject non-ASCII input first. `test_rv002_*`, mutations M21/M22 |

### Reviewed and found sound (now pinned by a test)
- RV-001: mutating a `NormalizedCall.args` dict after authorization is refused because the call hash is
  recomputed at execution (`test_rv001_*`).

### Suspected risks and limitations (not confirmed defects; no fix claimed)
| ID | Risk | Why it is acceptable now / next step |
|---|---|---|
| S-1 | Everything runs in one Python process: code in that process could call `MockToolBackend.run`, `SandboxState.replace_with`, or reach `store._verify.__self__` (the trusted channel) | SEC-002/008 hold for the agent-facing API (`Stack.step`, `gateway.authorize`); the threat model assumes the gateway/sandbox code is not compromised (A1). The model never executes Python. Revisit if agent-generated code is ever run |
| S-2 | A hung analyzer thread cannot be killed; two hung analyzers exhaust the pool and later B1/P1 calls time out | Fails closed (utility loss, not a security loss). M5 analyzer is pure and fast |
| S-3 | Usage counters in `authorize` are not locked | Agent loop is single-threaded; add a lock before any parallel execution |
| S-4 | The decision MAC covers (id, task, call hash, verdict) but not `reasons`/`mode`/`capability_id` | Those fields do not affect authorization; the audit record written at issue time is authoritative |
| S-5 | `max_calls` is consumed when ALLOW is issued, even if the tool then errors | Conservative direction |
| S-6 | The audit chain is tamper-*evident*, not tamper-proof; a writer of the whole DB can rebuild it | Matches the stated scope |
| S-7 | Analyzer context items are supplied by the agent loop; omitting items weakens B1/P1 but never B2 | Loop is trusted code in the experiment; runner should build items from tool results automatically (M4) |
| S-8 | A malformed policy raises `PolicyError` in `open_task` before any audit record | Fails closed; add an audit record in M6 |
| S-9 | ASCII-only e-mail/IBAN and 1e9 amount cap reject some legitimate real-world values | Data are synthetic; AgentDojo values to be checked in M5 |
| S-10 | M3 tools are not the benchmark's tools; semantics of the AgentDojo adapter untested | M5/M6 |

Untested paths: concurrency, file-backed SQLite audit path, `AuditLogger.close`, behavior with a
non-empty analyzer item list larger than memory limits.

## 6. Acceptance criteria

| Criterion | Result |
|---|---|
| All security invariant tests pass | PASS — SEC-001..015 each with positive and negative tests |
| Denied operations do not mutate sandbox state | PASS — per-invariant tests + randomized property test |
| Authorized operations update expected state | PASS |
| Decisions are auditable | PASS — one record per decision, hash chain verified; tampering detected |
| No real email / external transfer / destructive tool | PASS — sandbox import-boundary test; tools write only to `SandboxState` |
| No LLM required | PASS |

Cost: 0 THB. Required approvals: none for M3. Unchanged pending items: δ, REQ-AGT-4 threshold, oracle
adaptations F-2/F-3/F-4 (M2).
