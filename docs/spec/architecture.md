# Architecture (draft for approval)

## 1. Overview

```
 trusted channel                     untrusted data
 (runner/CLI)                         (tool outputs)
      │                                     ▲
      ▼                                     │
 TrustedTaskContext ──► Orchestrator ──► ModelAdapter (Ollama / test double)
 (task_id, prompt,          │  proposed ToolCall (untrusted)
  capability scope,         ▼
  policy hash)        ToolRegistry.validate  (name exists, args match schema, normalize)
                            │ NormalizedToolCall
                            ▼
                    AuthorizationGateway  ◄── config: B0 | B1 | B2 | P1
                    ├─ PolicyEngine (capabilities, deny-by-default)      [B2, P1]
                    ├─ ContextAnalyzer (provenance + instruction signals) [B1, P1]
                    └─ AuditLogger (every decision)                       [all]
                            │ Decision{ALLOW|DENY, reasons, decision_id}
                            ▼
                    Executor ── only accepts an ALLOW Decision bound to the call + task
                            │
                            ▼
                    Mock tools ──► SandboxState (isolated, in-memory, snapshot/diff)
                                          │
                                          ▼
                         Oracle (reads state diff only; independent of gateway)
```

## 2. Components and responsibilities

| Component | Module (created in milestone) | Responsibility |
|---|---|---|
| TrustedTaskContext | `policy/schemas.py` (M3) | Immutable: `task_id`, user prompt, capability set, policy hash, creation nonce. Created only by the runner/CLI. |
| Policy schema / CapabilityStore | `policy/schemas.py`, `policy/capability_store.py` (M3) | Capability = tool name + argument constraints (`equals`, `one_of`, `prefix` on normalized paths, `max`, recipient allowlists) + `max_calls`. Store is read-only to the agent loop; updates only through `grant()` requiring a trusted-channel token (SEC-008). |
| ToolRegistry | `agent/tool_registry.py` (M3) | Tool schemas (pydantic), `protected` flag, argument normalization (e-mail lowercase/strip, IBAN uppercase/no spaces, virtual POSIX path resolve, URL host lowercasing). Unknown tool → reject. |
| PolicyEngine | `policy/policy_engine.py` (M3) | Pure function `evaluate(ctx, call) -> PolicyVerdict`. Deny-by-default; explicit deny rules override allow; conflicting rules → DENY. |
| ContextAnalyzer | `defense/context_analyzer.py`, `defense/provenance.py` (M5) | Pure function of (trusted prompt, proposed call, untrusted context items with provenance). Signals below. Versioned config, thresholds, timeout. |
| AuthorizationGateway | `defense/authorization_gateway.py` (M3, analyzer hook M5) | Combines verdicts per configuration (§4). Exceptions/timeouts → DENY (SEC-013). Emits `Decision` with an unforgeable id bound to (task_id, call hash). |
| Executor + mock tools | `sandbox/executor.py`, `sandbox/mock_tools.py` (M3) | Executes only with a matching ALLOW decision; otherwise raises and leaves state untouched (SEC-003). |
| SandboxState | `sandbox/state.py` (M3) | Typed in-memory state with deep snapshot and structural diff. No I/O to the outside world. |
| AuditLogger | `storage/audit_logger.py` (M3) | Append-only JSONL/SQLite records with hash chaining for every decision and execution. |
| Oracle | `evaluation/oracle.py` (M3) | Evaluates goal predicates on (pre-state, post-state) only. Imports nothing from `defense/` or `policy/`. |
| ModelAdapter / Orchestrator | `agent/model_adapter.py`, `agent/orchestrator.py` (M4) | Ollama adapter + deterministic test double; step/time/token limits. |
| Benchmark adapter, runner, metrics, statistics | `evaluation/*` (M2/M6) | AgentDojo bridge (if feasible), experiment records, metrics, analysis. |

## 3. Context analyzer v0 (transparent heuristics; specified before tuning)

Inputs: trusted prompt `P`, normalized call `c`, list of untrusted items `U` (text + provenance: which
tool call produced it). Output: `AnalyzerVerdict{decision, score ∈ [0,1], signals[], version}`.

| Signal | Definition (deterministic) |
|---|---|
| S1 value provenance | For each security-relevant argument of `c` (recipient, IBAN, URL, path, amount): the value occurs in some untrusted item but **not** in `P` (after normalization) → signal fires. |
| S2 instruction-like content | Untrusted items contain imperative/override patterns (versioned regex list: "ignore (all\|previous)", "you must", "before you (solve\|continue)", "new instructions", impersonation of user/system, tool names as verbs, …). Score = matched patterns, capped. |
| S3 tool-intent alignment | `c.tool` is a side-effecting tool not lexically licensed by `P` (versioned keyword map tool → task verbs, e.g. `send_money` ↔ pay/transfer/send money). |
| S4 temporal coupling | `c` is proposed immediately after a tool output in which S2 fired. |

Decision: DENY if `score ≥ θ` where score is a fixed weighted sum (weights/θ tuned **only** on the
development split, then frozen). LLM-based analyzers are out of scope unless a measured reason appears.

## 4. Gateway decision semantics per configuration (exact)

Intercept point (all configs): after `ToolRegistry.validate` succeeds, before `Executor.execute`.
Malformed/unknown calls are rejected by the registry **in all configs** (they cannot execute in any
config; recorded as `invalid_call`, not as a defense success).

```
B0: decision = ALLOW
B1: a = analyzer(ctx, call, U)  (timeout/exception → DENY reason=ANALYZER_ERROR)
    decision = a.decision
B2: p = policy(ctx, call)       (exception → DENY reason=POLICY_ERROR)
    decision = p.decision
P1: p = policy(ctx, call); if p == DENY → DENY (analyzer not consulted, SEC-006)
    a = analyzer(ctx, call, U); decision = a.decision (error/timeout → DENY)
```

On DENY the agent receives a fixed, neutral tool-result message (`"Tool call denied by policy."`, same text
in all configs) and the loop continues; the model is not told which signal fired.

B1 scope note: the analyzer gates **every** proposed call (read-only and side-effecting) — same coverage
as the policy in B2. AgentDojo's native `transformers_pi_detector` (which inspects tool *outputs*) may be
run as an additional *external reference* baseline, reported separately from B1.

## 5. Isolation of the oracle
The oracle module may import only `sandbox.state` types and benchmark task definitions. A test enforces
this import boundary (REQ-ORC-2).
