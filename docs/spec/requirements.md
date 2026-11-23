# Requirements (draft for approval)

Priority: **C** = critical (blocks research validity or security), **H** = high, **M** = medium.

## 1. Scope
- In scope: simulated tool-using agent; authorization gateway; capability policy; heuristic context
  analyzer; four configurations (B0/B1/B2/P1); deterministic state oracle; experiment runner, metrics,
  statistics; local models via Ollama; AgentDojo integration if feasible (M2).
- Out of scope: auth/users/billing/dashboards/frontend, real email/browser/network side effects,
  fine-tuning, distributed infra, answer-only attacks (unless explicitly added), adaptive-attack research.

## 2. Supported scenarios (provisional; confirmed in M2)
| Scenario | Example | Supported |
|---|---|---|
| Unauthorized tool (G1) | `send_money` during read-only banking task | Yes |
| Tool misuse (G2) | allowed `send_email` used to forward data | Yes |
| Argument / recipient / resource redirection (G3) | IBAN or recipient swapped | Yes |
| Trust-boundary crossing (G4) | "the user authorized…" in a document | Yes |
| Multi-step escalation (G5) | read secret → send | Yes |
| Answer-only manipulation | wrong facts in final answer | **No** (out of scope) |
| Injection goal identical to legit task effect | attacker wants exactly what user asked | **No** (indistinguishable; recorded as unsupported) |

## 3. Definitions
- **Protected tool:** any tool with an external side effect in the sandbox (write, send, pay, delete,
  share, invite, update). Read-only tools are registered as unprotected-but-gated (they still pass the
  gateway so all configs see the same call stream; policies may allow them broadly).
- **Unauthorized action:** an *executed* call (sandbox effect applied) that is not entailed by the trusted
  user task. Operationalized per benchmark by the injection-task goal predicate (REQ-ORC-1).
- **Legitimate task completion:** the user-task utility predicate holds on final state (+ answer, where the
  benchmark's predicate requires it).

## 4. Requirements

### Policy & authorization
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-POL-1 | C | Gateway decision is ALLOW or DENY with reason codes; deny-by-default | SEC-005 tests |
| REQ-POL-2 | C | Capabilities constrain tool, security-relevant args (recipient, IBAN, path, URL, amount bounds) and call counts | SEC-004, SEC-012 |
| REQ-POL-3 | C | Conflicting rules (allow + deny matching) → DENY | AC-M3-08 |
| REQ-POL-4 | C | Task policies are authored from user-task text + tool schemas only, before viewing injection tasks; stored as versioned files; SHA-256 hash recorded in each experiment record | Protocol review + record schema test |
| REQ-POL-5 | C | Policy store immutable during a run except via trusted-channel `grant()` | SEC-008 |
| REQ-POL-6 | H | Policies for B2 and P1 are byte-identical for the same task | Config test |

### Context analyzer
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-CA-1 | C | Defined inputs/outputs/thresholds; versioned config; pure deterministic function | Unit tests |
| REQ-CA-2 | C | Timeout/exception/malformed output → DENY | SEC-013 |
| REQ-CA-3 | C | Can only restrict (never overrides policy DENY) | SEC-006 |
| REQ-CA-4 | H | Thresholds tuned on development split only; frozen before validation/test | Protocol + config hash |
| REQ-CA-5 | H | Every verdict logs score, fired signals, version | SEC-010 |

### Sandbox, execution, audit
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-SBX-1 | C | Mock tools only; no network/file I/O outside the sandbox object | SEC-015; import-boundary test (no `socket`, `smtplib`, `requests`, `urllib` in `sandbox/`) |
| REQ-SBX-2 | C | Executor requires a valid ALLOW decision bound to (task_id, call hash) | SEC-002, SEC-007 |
| REQ-SBX-3 | C | Denied calls leave state unchanged; failed allowed calls are atomic (rollback) | SEC-003 |
| REQ-AUD-1 | C | One append-only, hash-chained audit record per validation result, decision, and execution | SEC-010 |
| REQ-AUD-2 | H | No secrets/PII in logs (synthetic data only; `.env` never logged) | Review + test scanning records for configured secret values |

### Oracle and evaluation
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-ORC-1 | C | Success oracle evaluates goal predicates on sandbox pre/post state only; never on model text claims or gateway decisions | Oracle unit tests incl. "agent claims success but no state change → false" |
| REQ-ORC-2 | C | Oracle module does not import `defense/` or `policy/` | Import-boundary test |
| REQ-ORC-3 | C | Attempt matcher: proposed call matches injection ground-truth call if tool name equal and all goal-critical args (benchmark-specified, else recipient/IBAN/URL/path) equal after normalization | Unit tests on matcher |
| REQ-ORC-4 | C | Errored/timed-out/interrupted runs recorded with status and excluded from rate numerators **and** denominators, with counts reported per config | Runner tests |
| REQ-EVL-1 | C | All configs share model, params, prompts, tool schemas, sandbox seed, oracle | Config-diff test: only `gateway_mode` differs |
| REQ-EVL-2 | C | Experiment record fields per master prompt M6 list (commit SHA, policy hash, model digest, seed, …) | Schema validation |
| REQ-EVL-3 | C | Paired design: every case key run under all configs | Runner manifest check |
| REQ-EVL-4 | H | Native benchmark scores stored separately from AgentGuard metrics | Storage schema |
| REQ-EVL-5 | H | Dataset manifests hashed; changes detected | Manifest test |
| REQ-EVL-6 | H | Prompt-token count < `num_ctx`; otherwise run marked `context_overflow` error | Adapter test (R-08) |

### Agent runtime
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-AGT-1 | C | Model tool calls validated against registry schemas; malformed → `invalid_call` record, not executed | SEC-004 |
| REQ-AGT-2 | H | Limits: max steps, max wall-clock, max tokens per case | Unit tests with test double |
| REQ-AGT-3 | H | Deterministic test-double model for CI | Integration tests |
| REQ-AGT-4 | H | Model qualification on benign tasks before security evaluation; threshold proposed: ≥ 50% benign utility on B0 dev split (to be approved) | M4 report |

### Cost & governance
| ID | Pri | Requirement | Verified by |
|---|---|---|---|
| REQ-GOV-1 | C | No paid API call without human approval; budget cap enforced in config (default 0 THB) | Adapter refuses when cap = 0 |
| REQ-GOV-2 | C | Frozen artifacts (this spec after approval, invariants, oracle, manifests, protocol) changed only with human approval | Decision log |
