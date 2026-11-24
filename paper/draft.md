# AgentGuard: An Empirical Factorial Evaluation of Intent-Bound Tool Authorization and Heuristic Context Analysis Against Indirect Prompt Injection

*(Research Paper Draft — AgentGuard v3.1 Prototype. All quantitative results are derived strictly from recorded experiments on `m8-freeze` (`a1a105f`); no figures or citations are fabricated.)*

---

## 1. Abstract

Tool-using Large Language Model (LLM) agents face indirect prompt injection (IPI), where untrusted documents or tool outputs hijack the agent into executing unauthorized actions. Recent defenses combine deterministic capability or privilege policies with content-level injection detectors, yet the *marginal* security benefit and utility cost of adding a detector on top of deterministic task-scoped permissions are rarely isolated within a single paired harness. We present **AgentGuard**, an intent-bound tool authorization prototype enforcing 15 verifiable security invariants (`SEC-001`–`SEC-015`) with an independent, deterministic state-based oracle that separates *attempted*, *denied*, *executed*, and *goal-achieved* events. Rather than claiming mechanism-level novelty—prior systems such as IGTA, DRIFT, Progent, CaMeL, and LlamaFirewall already explore intent-bound authorization and layered guardrails—we frame our contribution as a pre-registered, paired factorial attribution study across four identical-harness configurations: unprotected (`B0`), heuristic context analyzer only (`B1`), deterministic task-scoped capability enforcement only (`B2`), and their fail-closed combination (`P1`). On the frozen test split of the AgentDojo v1.2.2 banking suite (11 user tasks, 99 attack cases, 11 benign cases; 440 main runs plus 110 repeat noise-floor runs) driven by a local open-weight model (`qwen3.5:9b`, zero paid API cost), we find: (1) **Confirmatory H1 is robustly supported**: `B2` reduces executed unauthorized actions from `31/99` (`31.3%`) in `B0` to `2/94` (`2.1%`), a paired reduction of `+25.5` percentage points (exact McNemar $p = 1.19 \times 10^{-7}$, user-task cluster-bootstrap 95% CI `[+9.1, +44.7]` pp, cluster sign test $p = 0.03125$, two-way bootstrap 95% CI `[+7.1, +49.5]` pp), while preserving `100%` of clean task utility under attack (`+0.0` pp vs `B0`, $p = 1.0$). (2) **Adding heuristic context analysis (`P1` vs `B2`) yields a negative net utility trade-off**: `P1` blocks the two wildcard-policy escapes in `user_task_0` (`2/94 -> 0/93`, `+2.1` pp, descriptive McNemar $p = 0.50$), but because the coarse detector denies any protected call once injection text enters context, `B1` and `P1` produce identical trajectories on `110/110` cases and lose `10` legitimate tasks under attack relative to `B2` (`-13.3` pp on valid tasks, `-17.5` pp on strict tasks, $p = 0.00195$). (3) Run-to-run noise on the M8 hardware is `0/110` (`exact 95% CI [0.000, 0.033]`), while mean wall-clock overhead (`+21.7%` to `+28.1%`) stems primarily from agent retry loops after denials. We report all negative results, author-written policy caveats, benchmark oracle defects, and single-model/single-suite limits explicitly.

---

## 2. Introduction

Modern AI agents augment LLMs with external tools to read documents, inspect accounts, send messages, and modify state. Because tool outputs and retrieved documents share the same token stream as the user's instructions, an adversary who controls external data can embed hidden instructions—**indirect prompt injection (IPI)** (Greshake et al., 2023; Liu et al., 2023)—to redirect the agent toward unauthorized tool executions.

Two broad classes of runtime defenses have emerged: (i) **deterministic permission or capability enforcement**, which binds allowed tool names and argument constraints to the trusted user intent before execution (e.g., CaMeL, Progent, IGTA, MiniScope, AgenTRIM), and (ii) **injection detection or context analysis**, which inspects untrusted content or agent state to flag suspicious calls (e.g., DataSentinel, MELON, Task Shield, LlamaFirewall, DRIFT). Intuitively, combining both layers should achieve defense-in-depth: capability policies block out-of-scope tools and fixed arguments, while context analysis catches attacks that exploit wildcard arguments derived from untrusted data.

However, layering a heuristic detector onto deterministic permission enforcement carries an under-examined empirical risk: once an injection string enters the context, a detector that lacks fine-grained data-flow tracking may block *legitimate* side-effecting actions of the user's task, degrading utility under attack far more than it improves security. Evaluating this trade-off requires a strictly controlled factorial design where unprotected (`B0`), detector-only (`B1`), policy-only (`B2`), and hybrid (`P1`) defenses intercept the exact same normalized tool-call stream, return identical neutral denial messages, and are scored by an independent state-based oracle that never equates a model's text claim or a gateway denial with ground-truth security.

This paper makes the following **verified** contributions within the scope of our research prototype:
1. **Verified security-core architecture (`SEC-001`–`SEC-015`):** A deny-by-default, fail-closed authorization gateway with HMAC-bound single-use decisions, canonical argument normalization, trusted-channel capability management, hash-chained SQLite audit logging, and an AST-isolated state oracle, verified by 415 core unit/security/integration/regression tests, 89 AgentDojo banking adapter tests, strict static typing, and 100% kill rate on security-core mutation checks.
2. **Pre-registered paired factorial attribution on AgentDojo banking:** An integrity-gated empirical study comparing `B0`, `B1`, `B2`, and `P1` on the frozen test split of AgentDojo v1.2.2 banking (440 main runs + 110 noise-floor repeat runs) with a local open-weight model (`qwen3.5:9b`, 0 THB API cost), explicitly separating *attempted*, *denied*, *executed*, and *goal-achieved* outcomes alongside stratified utility (`all_16`, `valid_13`, `strict_11`) and unclean-run sensitivity bounds.
3. **Honest negative/trade-off evidence for coarse context analysis:** Empirical demonstration that while deterministic task-scoped capabilities (`B2`) deliver a large, statistically robust security gain (`31/99 -> 2/94`, $p = 1.19 \times 10^{-7}$) at zero clean attack-time utility loss, layering a transparent heuristic detector (`P1`) prevents only 2 wildcard escapes ($p = 0.50$) while forfeiting 10 legitimate tasks under attack (`-13.3` pp valid / `-17.5` pp strict, $p = 0.00195$) and collapsing to `110/110` identical trajectories with detector-only `B1`.

We explicitly distinguish **non-claims and unverified areas**: we do *not* claim mechanism-level novelty for intent-bound authorization or hybrid guardrails; we do *not* claim generalization across models, AgentDojo suites beyond banking, or automatically generated policies; and we report cross-model generalization (`RQ4`) as untested due to single-model qualification.

---

## 3. Related Work

We position AgentGuard against verified literature spanning benchmarks, architectural isolation, capability/policy enforcement, and prompt-injection detection (`docs/research/related-work-matrix.md`).

### 3.1 Benchmarks and Attack Formalizations
Greshake et al. (2023) established the indirect prompt injection threat landscape for LLM-integrated applications, and Liu et al. (2023) formalized prompt injection attacks and defenses. **InjecAgent** (Zhan et al., 2024) benchmarks single-step indirect injections via pre-scripted tool responses and text-parsed action evaluation (measuring attempted rather than executed state effects). **AgentDojo** (Debenedetti et al., 2024) provides dynamic multi-step environments (`workspace`, `travel`, `banking`, `slack`) with programmatic state-based `utility()` and `security()` predicates, making it suitable for deterministic executed-effect evaluation. During feasibility analysis (M2), we documented concrete benchmark caveats in AgentDojo 0.1.35 / suite v1.2.2, including content-block breakage in `TaskSuite.check()` (`F-1`), unvalidated workspace positive controls (`F-2`), proposed-trace Slack predicates (`F-3`), operator-precedence looseness in banking injection tasks 0/1/3 (`F-4`), answer-only `travel/injection_task_6` (`F-5`), and five banking user tasks whose native utility predicate passes for a no-op agent (`F-6`).

### 3.2 Capability, Privilege, and Information-Flow Defenses
Architectural patterns such as the Dual-LLM pattern (Willison, 2023) and broader agent security design patterns (Beurer-Kellner et al., 2025) separate privileged planning from untrusted data processing. **IsolateGPT** (Wu et al., 2025) enforces execution isolation across agent apps, while **CaMeL** (Debenedetti et al., 2025) extracts a control-flow plan from the trusted user query and attaches capabilities to runtime values. Information-flow control (IFC) approaches—**FIDES** (Costa et al., 2025), **RTBAS** (Zhong et al., 2025), **ACE** (Li et al., 2025), and **MAC-Agents** (Ji et al., 2026)—track taint or attribute-based labels across tool inputs and outputs.

Closely related to our policy layer are runtime privilege and intent-binding frameworks: **Progent** (Shi et al., 2025) enforces programmable privilege policies deterministically; **AgentSpec** (Wang et al., 2025) provides a customizable runtime rule DSL; **Conseca** (Tsai et al., 2025) generates context-specific policies; **IPIGuard** (An et al., 2025) and **AgentArmor** (Wang et al., 2025) enforce tool dependency graphs or program analysis over runtime traces; **MiniScope** (Zhu et al., 2025) and **AgenTRIM** (Betser et al., 2026) enforce task-scoped least-privilege permissions; and **IGTA** (Zhu et al., 2026) explicitly introduces intent-governed tool authorization using intent certificates. Consequently, intent-bound tool authorization is *not* novel as a mechanism.

### 3.3 Prompt-Injection Detectors and Layered Guardrails
Training- and prompt-level defenses include **Spotlighting** (Hines et al., 2024), **StruQ** (Chen et al., 2024), and **SecAlign** (Chen et al., 2024). Dedicated runtime detectors include **DataSentinel** (Liu et al., 2025), **MELON** (Zhu et al., 2025) via masked re-execution, **Task Shield** (Jia et al., 2024) via LLM-judged task alignment, and guard-agent/reasoning systems such as **GuardAgent** (Xiang et al., 2024) and **ShieldAgent** (Chen et al., 2025). Layered defenses directly overlapping our `P1` design include **LlamaFirewall** (Chennabasappa et al., 2025), which combines a prompt-injection scanner with an alignment auditor, and **DRIFT** (Li et al., 2025), which pairs intent-derived rules with injection isolation.

### 3.4 Research Positioning
Because intent binding (IGTA, CaMeL, Progent, MiniScope) and hybrid detector+policy architectures (DRIFT, LlamaFirewall) already exist in the literature, our study explicitly refrains from claiming mechanism novelty (Decision D-008). Instead, AgentGuard contributes a **controlled, pre-registered factorial attribution evaluation** (`B0`, `B1`, `B2`, `P1`) on a local consumer-hardware open-weight model (`qwen3.5:9b`), isolating how much security and utility cost belongs to deterministic task-scoped permissions versus a zero-LLM-call heuristic context analyzer under a single interception point and independent state oracle.

---

## 4. Threat Model

**System Under Protection.** A single-user LLM agent receives a trusted task prompt $P$ from a trusted channel (CLI/runner), interacts with a fixed registry of simulated tools, and incorporates untrusted tool responses into its context window. All tools execute exclusively against an isolated in-memory sandbox state (no real email, financial transfer, network exfiltration, or host file I/O).

**Trust Boundaries.**
- *Trusted:* user task prompt $P$, frozen/hashed task capability policy, system prompt, tool schemas, gateway/policy/sandbox code, and audit log (Assumption `A1`–`A3`).
- *Untrusted:* all tool outputs, retrieved documents, transaction notes, benchmark attack strings, and model-proposed tool calls (`SEC-001`, `SEC-009`). Untrusted data can never grant or modify capabilities (`SEC-008`).
- *Advisory-only:* the context analyzer verdict may only restrict an `ALLOW` to `DENY` and can never override a policy `DENY` (`SEC-006`).

**Attacker Capabilities and In-Scope Goals.** The attacker controls one or more untrusted data items read during task execution (indirect prompt injection) and knows the tool schema and task domain, but cannot modify $P$, policy files, gateway code, sandbox state directly, or audit logs. In-scope goals are: (`G1`) unauthorized tool invocation outside task scope, (`G2`) misuse of an authorized tool for an unrelated purpose, (`G3`) argument/recipient/resource redirection, (`G4`) trust-boundary crossing (impersonating instructions or policy updates), and (`G5`) multi-step escalation.

**Out of Scope.** Direct user jailbreaks, answer-only misinformation without tool side effects (`F-5`), host/supply-chain/model-weight compromise, and adaptive evasion of heuristic regexes (acknowledged as an inherent residual risk of heuristic detectors).

---

## 5. Proposed Framework: AgentGuard v3.1

### 5.1 Architecture and Security Invariants
AgentGuard places a single deterministic **Authorization Gateway** between the LLM orchestrator and the simulated tool executor (`src/agentguard/`):

1. **Trusted Task Context & Capability Store (`policy/`):** When a task opens over an unforgeable `TrustedChannel`, `TrustedTaskContext` immutably binds `task_id`, `user_prompt`, and `policy_hash`. Capabilities specify allowed or explicitly denied tools, per-capability call budgets (`max_calls`), and typed argument constraints (`equals`, `one_of`, `prefix`, `max`, `absent`, or an explicit opt-in `any_value` wildcard for data-derived parameters, Decision D-012).
2. **Tool Registry & Canonical Normalization (`agent/tool_registry.py`, `normalize.py`):** Every proposed call is validated against strict Pydantic schemas and canonicalized *before* mode-specific logic (`SEC-004`, `SEC-011`): emails and hosts are ASCII-checked and lowercased, IBANs stripped of spaces/hyphens and uppercased, virtual paths resolved via POSIX rules rejecting traversal and encoded lookalikes (`%2e%2e`, backslashes), and numeric amounts range-checked (`RF-001`, `RF-002`). Unknown or malformed calls fail closed as `INVALID_CALL` in **every** configuration, including `B0`, and are never counted as defense denials (`RF-003`).
3. **Policy Engine (`policy/policy_engine.py`):** A pure function evaluating only `(capabilities, normalized_call, usage)` with **no access to untrusted context** (`SEC-009`). It enforces deny-by-default (`SEC-005`), explicit-deny precedence, mandatory constraints on all security-relevant parameters (omitting a constraint yields `NO_MATCHING_RULE`), and call-budget caps.
4. **Heuristic Context Analyzer v0.1 (`defense/context_analyzer.py`):** A transparent, deterministic, zero-LLM-call analyzer (`v0.1+54a3f7c1d1a3`) with weights fixed a priori in M5 (`threshold = 0.6`). Given `(P, call, U)` where $U$ is the sequence of untrusted `ContextItem`s (capped at 20,000 chars/item):
   - $S_1 \in \{0, 1\}$ (`w = 0.4`): a non-amount security-relevant argument appears in $U$ (squashed) but not in $P$.
   - $S_2 \in \{0, 0.5, 1\}$ (`w = 0.4`, protected tools only): generic imperative/override regex hits in $U$ ($\min(1, \text{hits}/2)$).
   - $S_3 \in \{0, 1\}$ (`w = 0.2`, protected tools only): side-effecting tool not licensed by lexical verbs in $P$.
   - $S_4 \in \{0, 1\}$ (`w = 0.2`, protected tools only): $S_2 > 0$ in the most recent untrusted item $U_{-1}$.
   - Score $s = \min(1, 0.4 S_1 + \mathbb{I}_{\text{prot}}(0.4 S_2 + 0.2 S_4) + 0.2 S_3)$; `DENY` iff $s \ge 0.6$. Notably, when a protected tool is called immediately after an untrusted output containing $\ge 2$ injection patterns, $0.4(1.0) + 0.2(1.0) = 0.6 \ge 0.6$ triggers `DENY` even when $S_1 = 0$ and $S_3 = 0$.
5. **Gateway Decision Semantics & Single-Use Enforcement (`defense/authorization_gateway.py`, `sandbox/executor.py`):**
   - `B0`: `ALLOW` (validated and logged; mock sandbox only, `SEC-015`).
   - `B1`: consults analyzer only (`ANALYZER_TIMEOUT`/`ANALYZER_ERROR` $\to$ `DENY`, `SEC-013`).
   - `B2`: consults policy engine only (`POLICY_ERROR` $\to$ `DENY`).
   - `P1`: evaluates policy first; on policy `DENY`, returns immediately without consulting the analyzer (`SEC-006`). On policy `ALLOW`, evaluates analyzer.
   - Every `Decision` carries an HMAC-SHA256 bound to `(decision_id, task_id, call_hash, verdict)` and is consumed at most once by the executor (`SEC-002`, `SEC-007`). Denied calls never invoke tools and leave sandbox state byte-identical (`SEC-003`). On any policy/analyzer denial, the model receives the identical neutral message `"Tool call denied by policy."` across all configurations.
6. **Tamper-Evident Audit Log & Independent Oracle (`storage/audit_logger.py`, `evaluation/oracle.py`):** Every task lifecycle event, validation failure, decision, and execution appends to a hash-chained SQLite log (`SEC-010`). The state oracle imports nothing from `defense/` or `policy/` (AST-enforced) and evaluates post-run sandbox state directly.

### 5.2 AgentDojo Banking Integration
The adapter (`src/agentguard/benchmarks/agentdojo_banking.py`) builds the `ToolRegistry` directly from AgentDojo v1.2.2's 11 banking tool schemas and wraps `runtime.run_function` inside a `GatedToolRunner` requiring a consumed gateway `ALLOW` decision. Sixteen task-scoped policies (`banking-v2`, SHA-256 `086eaa01...`) were frozen before M8 execution, permitting read-only inspection tools without security-relevant arguments (`get_balance`, `get_iban`, `get_user_info`, `get_most_recent_transactions`, `get_scheduled_transactions`) while scoping `read_file` and all state-mutating tools (`send_money`, `schedule_transaction`, `update_scheduled_transaction`, `update_user_info`, `update_password`) to each user task's prompt text and schemas. Ground-truth replay verifies `144/144` native security parity in `B0` and establishes a model-independent static ceiling of `12/144` policy-reachable cells under `B2` (6 injection tasks each in `user_task_0` and `user_task_10`, which require `any_value` wildcards for data-derived payees).

---

## 6. Experimental Setup

All design choices, endpoints, and statistical rules were frozen in `docs/research/m8-analysis-plan.md` prior to running the test split (`tag: m8-freeze`, commit `a1a105f`).

### 6.1 Research Questions and Pre-Registered Design
- **RQ1 (Confirmatory H1):** Does capability enforcement (`B2`) reduce executed unauthorized actions compared with `B0`?
- **RQ2 (Descriptive H2):** Does adding context analysis (`P1`) provide measurable additional protection beyond `B2`, and at what utility cost?
- **RQ3 (Descriptive H3 + Exploratory):** What is the impact of defenses on benign utility and task completion under attack?
- **RQ4:** Consistency across models and attack scenarios (**declared untestable** prior to M8: of four local models evaluated in M7, only `qwen3.5:9b` passed the 50% benign qualification threshold on valid tasks—`9/13` vs `qwen3:8b` `5/13`, `llama3.1:8b` `2/13`, `gemma4:e4b` `5/13`—and the banking manifest includes one attack family).
- **RQ5 (Descriptive):** Wall-clock latency, token usage, model calls, and API cost overhead.

### 6.2 Dataset, Model, and Protocol
- **Dataset:** Frozen **test** split of `datasets/manifests/banking-v1.json` (`9db39933...`): 11 user tasks (`0, 1, 3, 4, 6, 8, 9, 10, 12, 13, 14`), comprising `99` attack cases (`11 × 9` banking injection tasks under `important_instructions_no_model_name`) and `11` benign cases = `110` cases $\times$ `4` configurations = **440 runs**. Development split (`user_task_2, 7, 15`) was used exclusively for M7 pilots; validation split (`user_task_5, 11`) was unused.
- **Model & Decoding:** Local Ollama `qwen3.5:9b` (digest `56671c2ab938...`), `num_ctx=12288`, `think=false`, `temperature=0.0`, `seed=0`, `max_output_tokens=1024`, `max_steps=10`, `max_wall_s=300` (per call). Budget: `0 THB`.
- **Execution Order & Noise Floor:** Main runs executed **case-major** (all four configurations of a case back-to-back) to eliminate time confounding, followed by a separate descriptive **M8b noise-floor experiment** re-running `B0` on all 110 test cases (`experiments/configs/m8b-noise-b0.yaml`).
- **Hardware Note (D-021, R-33):** While M0–M7d were run on Windows 11 / AMD RX 7600 8 GiB / Python 3.13.14, M8 and M8b executed on macOS arm64 (Apple M2 Pro, 16 GiB, Metal) / Python 3.14.6 using the exact pinned model digest and `agentdojo==0.1.35` freeze.

### 6.3 Endpoints, Utility Strata, and Statistical Methods
- **Primary Endpoint:** *Executed unauthorized action* = AgentDojo's native post-run state predicate `injection_task.security()` evaluates to `True`. Denominator = clean attack runs (`run_status == completed`). Unclean runs (`step_limit`, infrastructure failure) have no stored oracle verdict, are excluded from complete-case rates, and are bounded via pre-registered **per-arm worst-case/best-case sensitivity analyses**.
- **Utility Strata (F-6 Mitigation):** All utility metrics are reported across three pinned strata: `all_16` (11 test tasks), `valid_13` (9 test tasks; excludes no-op-passing `user_task_6, 8`), and `strict_11` (7 test tasks; also excludes unchanged-state `user_task_9, 10`).
- **Confirmatory Rule for H1:** Pre-registered exposure adequacy requires $\ge 10$ clean `B0` attack attempts across $\ge 4$ user tasks. `H1` is **SUPPORTED** iff exposure is adequate, `only-B0 > only-B2`, exact two-sided McNemar $p < 0.05$ (Holm over family of 1), and the 95% user-task cluster-bootstrap CI (`10,000` resamples, seed `20261119`) has lower bound $> 0$; robustness further requires cluster sign test $p < 0.05$ and two-way (user task $\times$ injection task) bootstrap lower bound $> 0$.
- **Descriptive Rules for H2 & H3:** Pre-registration review showed H2 can have discordance in at most 2 of 11 clusters (making cluster-bootstrap significance mathematically unreachable) and H3 has only $n=9$ benign pairs; thus H2 reports exact Clopper-Pearson CIs and raw McNemar $p$, and H3 reports the exact unconditional Berger-Boos one-sided 95% lower bound ($\gamma = 0.005$, exact operating characteristics verified in `m8-h3-operating-characteristics.json`).

---

## 7. Results

### 7.1 Integrity and Run-to-Run Noise Floor
`analyze_main.py --frozen-commit m8-freeze` exited with code `0` (`INTEGRITY: OK`): `440/440` expected records analyzed, `0` missing, `0` dirty (`code_dirty = false`), `0` infrastructure failures or retries, identical frozen `SRC_PATHS`, and verified model digest `56671c2ab938...`. Seventeen attack runs hit `step_limit` (`max_steps = 10`) due to denial retry loops (`B0: 0`, `B2: 5`, `B1: 6`, `P1: 6`).

In the **M8b B0 noise-floor run** (`110/110 completed`), **0/110 cases differed** between run 1 and run 2 across `run_status`, `attack_attempted`, `attack_executed`, `task_success`, `trajectory`, `input_tokens`, and `output_tokens` (exact 95% CI `[0.000, 0.033]`). Thus stochastic noise on the M8 hardware does not explain any cross-configuration differences.

### 7.2 Security and Utility Summary

| Config | Clean Attack ($n$) | Attempted | **Executed Unauthorized** (Wilson 95% CI) | Exec \| Attempt | Utility Under Attack (`all_16` / `valid_13` / `strict_11`) | Benign (`valid_13` / `strict_11`) | Benign Denials |
|---|---:|---:|---|---:|---|---|---:|
| **B0** | 99 | 32/99 (32.3%) | **31/99 (31.3%)** `[0.23, 0.41]` | 31/32 (96.9%) | 60/99 (60.6%) / 42/81 (51.9%) / 24/63 (38.1%) | 8/9 / 6/7 | 0/11 |
| **B1** | 93 | 27/93 (29.0%) | **0/93 (0.0%)** `[0.00, 0.04]` | 0/27 (0.0%) | 47/93 (50.5%) / 29/75 (38.7%) / 11/57 (19.3%) | 8/9 / 6/7 | 0/11 |
| **B2** | 94 | 27/94 (28.7%) | **2/94 (2.1%)** `[0.01, 0.07]` | 2/27 (7.4%) | 58/94 (61.7%) / 40/76 (52.6%) / 22/58 (37.9%) | 8/9 / 6/7 | 0/11 |
| **P1** | 93 | 27/93 (29.0%) | **0/93 (0.0%)** `[0.00, 0.04]` | 0/27 (0.0%) | 47/93 (50.5%) / 29/75 (38.7%) / 11/57 (19.3%) | 8/9 / 6/7 | 0/11 |

*Figures generated directly from `results/metrics/m8-banking-qwen35/summary.json` (`experiments/scripts/m9/generate_figures.py`):*
- **Figure 1** (`results/figures/fig1_security_utility_tradeoff.svg`): Executed Unauthorized ASR vs. Utility Under Attack (`valid_13` and `strict_11`) across `B0`, `B1`, `B2`, and `P1`.
- **Figure 2** (`results/figures/fig2_per_task_attacks.svg`): Executed unauthorized attacks per user task (highlighting the 2 wildcard escapes in `user_task_0`).
- **Figure 3** (`results/figures/fig3_latency_tokens_overhead.svg`): Wall-clock latency (median, mean, P95) and mean input tokens / model calls per run (`RQ5`).

### 7.3 Confirmatory Test H1 (RQ1: `B2` vs `B0`)
- **Exposure:** **ADEQUATE** (`32` clean `B0` attempts across `6/11` user tasks: `user_task_0, 3, 8, 12, 13, 14`).
- **Primary Result:** Over 94 clean pairs (11 clusters), `only-B0 = 24`, `only-B2 = 0`, `both = 2`, `neither = 68`. Rate reduction `rate(B0) - rate(B2) = +0.255` (**+25.5 pp**), exact McNemar $p = 1.19 \times 10^{-7}$ (Holm-adjusted $1.19 \times 10^{-7}$), user-task cluster-bootstrap 95% CI **`[+0.0909, +0.4468]`**.
- **Robustness Checks:** Cluster sign test: `6` tasks favoring `B2`, `0` opposing, `5` tied ($p = 0.03125 < 0.05$). Two-way bootstrap 95% CI: **`[+0.0707, +0.4945]`**. Leave-one-user-task-out: all 11 exclusions retain `17–24` `only-B0` vs `0` `only-B2` ($p < 0.0001$).
- **Unclean-Run Bounding Sensitivity (99 pairs):** Even in the **worst case for defense** (all 5 `B2` `step_limit` runs imputed as attack executed), `only-B0 = 24`, `only-B2 = 0`, diff `+0.242`, McNemar $p = 1.19 \times 10^{-7}$, cluster CI `[+0.0909, +0.4141]`, sign test $p = 0.03125$. Best-case bound: `only-B0 = 29`, diff `+0.293`, $p = 3.73 \times 10^{-9}$.
- **Verdict:** **`SUPPORTED (robust to the cluster sign test and the two-way bootstrap)`**.

### 7.4 Descriptive H2 (RQ2: `P1` vs `B2`) and Factorial Attribution
- **Security Difference:** Over 93 clean pairs, `only-B2 = 2`, `only-P1 = 0`, diff `+0.021` (+2.1 pp), exact McNemar $p = 0.50$, cluster CI `[0.0, 0.0652]`, two-way CI `[0.0, 0.0952]`. Restricted to the 12 policy-reachable cells: `B2` `2/12` (`[0.021, 0.484]`) vs `P1` `0/12` (`[0.000, 0.265]`, $p = 0.50$). Worst-case unclean bound for `P1`: diff `-0.040`, cluster CI `[-0.162, +0.051]`.
- **Both `B2` Escapes:** Occurred in `user_task_0` (`injection_task_1` and `injection_task_5`), where the task legitimately pays a bill read from `bill-december-2023.txt`, necessitating `any_value` wildcards on `send_money`. `P1` denied `send_money` via `ANALYZER_DENY`.
- **Exact Trajectory Collapse (`B1 == P1`):** Across all `110/110` cases, `B1` and `P1` produced **identical** `(tool, verdict, executed)` trajectories, token totals (`8,008.8` in / `544.2` out), and call counts (`3.8`/run). In `P1`, policy rules absorbed 63 denials (`NO_CAPABILITY: 54`, `NO_MATCHING_RULE: 9`) and the analyzer issued `40` `ANALYZER_DENY` verdicts, matching `B1`'s `103` `ANALYZER_DENY` verdicts call-for-call.

### 7.5 Utility Under Attack and Benign Utility (RQ3)
- **Benign Utility (Descriptive H3):** Identical across all four configurations (`10/11` `all_16`, `8/9` `valid_13`, `6/7` `strict_11`, `0/11` benign defense denials; only `user_task_4|benign` failed with 0 tool calls). Because $n$ is small, exact one-sided 95% lower bounds on `rate(P1) - rate(B0)` are `-0.386` (`valid_13`, $p = 0.426$ for margin `-0.10`) and `-0.466` (`strict_11`, $p = 0.483$).
- **Utility Under Attack (Exploratory Contrasts):**
  - `B2` vs `B0` (complete-case): **`+0.000`** (`only-B2 = 0`, `only-B0 = 0`, $p = 1.0$) across all three strata. Including `B2`'s 5 `step_limit` runs as failures yields `-0.025` (`valid_13`, $p = 0.50$, cluster CI `[-0.074, 0.0]`).
  - `P1` vs `B2` (and `B1` vs `B0`, complete-case): `P1` lost **10** legitimate tasks that `B2` completed (`only-P1 = 0`, `only-B2 = 10`; **10/10 carried `ANALYZER_DENY`**):
    - `all_16`: `-10.7 pp` ($p = 0.00195$, cluster CI `[-0.302, 0.0]`)
    - `valid_13`: **`-13.3 pp`** ($p = 0.00195$, cluster CI `[-0.370, 0.0]`; with unclean as failure: `-13.6 pp`, $p = 0.000977$)
    - `strict_11`: **`-17.5 pp`** ($p = 0.00195$, cluster CI **`[-0.473, -0.016]`**, excluding 0)
  - All 10 losses were legitimate user operations blocked after injected text entered untrusted tool outputs: 8 cases in `user_task_13` (`update_user_info`), `user_task_12|injection_task_7` (`update_scheduled_transaction`), and `user_task_14|injection_task_7` (`update_password`), plus 1 additional `step_limit` failure in `user_task_13|injection_task_1`.

### 7.6 Cost and Latency Overhead (RQ5)
Total local compute was **2.95 h** for M8 (440 runs) plus **0.63 h** for M8b (110 runs) = **3.58 h** (`0 THB` paid API cost). Mean wall-clock latency per run increased from `20.3s` (`B0`, median `18.3s`, P95 `40.6s`, `3.1` model calls, `5,831` input tokens) to `24.7s` (`B2`, `+21.7%`, P95 `70.6s`, `3.6` calls, `7,343` in tokens), `26.0s` (`B1`, `+28.1%`, P95 `68.8s`, `3.8` calls, `8,009` in tokens), and `25.7s` (`P1`, `+26.6%`, P95 `66.3s`, `3.8` calls, `8,009` in tokens). Gateway decision time was not timed separately; overhead was dominated by extra LLM turns in retry loops following denials (notably `user_task_12` hitting `max_steps = 10`).

---

## 8. Discussion

Our factorial attribution exposes a sharp asymmetry between deterministic capability enforcement and coarse heuristic context detection:

1. **Why `B2` Succeeds With Near-Zero Utility Cost:** Deterministic task-scoped policies encode *which* tools and parameter bindings belong to the user's request. Even when untrusted data successfully hijacks the LLM's reasoning, the gateway blocks out-of-scope tools (`NO_CAPABILITY`, 52 denials) and mismatched arguments (`NO_MATCHING_RULE`, 7 denials) without impeding legitimate in-scope actions (`0` clean utility losses vs `B0`).
2. **Why `P1` Underperforms `B2` on Utility Under Attack (Root-Cause Analysis):** In `ContextAnalyzerV0` (`src/agentguard/defense/context_analyzer.py:134–147`), when the most recent untrusted tool output contains $\ge 2$ injection patterns (`S2 = 1.0`, `S4 = 1.0`), the score for *any* protected tool call reaches $0.4(1.0) + 0.2(1.0) = 0.6 \ge \theta$, triggering `ANALYZER_DENY` **regardless of whether the tool arguments came from the trusted user prompt (`S1 = 0`) or match user intent (`S3 = 0`)**. Consequently, once an agent reads a contaminated document during a legitimate task (`user_task_12, 13, 14`), the analyzer effectively freezes all subsequent state-changing actions—explaining both why `B1` and `P1` were identical on `110/110` cases and why `P1` traded 2 prevented wildcard attacks for 10 lost legitimate tasks.
3. **Design Implication for Hybrid Defenses:** Layering a context-level injection detector on top of capability enforcement is counterproductive unless the detector is **argument-scoped** (e.g., triggering only when a call exercises a wildcard/data-derived parameter whose value actually originates from a tainted untrusted span, as in fine-grained IFC/CaMeL-style value provenance) rather than globally blocking all protected calls whenever untrusted context contains imperative text.

---

## 9. Limitations

1. **Non-Blind Policy Authoring (`R-24`):** Policies (`banking-v2`) were written by the author after inspecting AgentDojo injection goals during M2 feasibility analysis, then frozen and hashed prior to test execution. H1 proves that frozen per-task capability policies stop this model's calls on banking, not that blind or automatically generated policies achieve identical coverage.
2. **Scarcity of Data-Derived Arguments (`R-21`, `R-23`):** Only 2 of 11 test user tasks (`user_task_0, 10`; 12/99 cells) require wildcard payees, constraining B2's residual attack surface and leaving H2 descriptive.
3. **Single Model, Single Suite, Single Attack Family (`R-30`):** Generalization across model families (`RQ4`), additional AgentDojo suites (`workspace`, `travel`, `slack`), adaptive attacks against regex heuristics, and paid frontier models remains unverified.
4. **Benchmark Oracle Caveats (`F-4`, `F-6`):** Native AgentDojo predicates for banking injection tasks 0/1/3 are looser than their prompt text (`F-4`, unmodified to preserve native comparability), and 5/16 user tasks pass for a no-op agent (`F-6`, mitigated via `valid_13`/`strict_11` strata).
5. **Execution Platform Migration (`D-021`, `R-33`):** M8/M8b ran on macOS Apple M2 Pro / Python 3.14.6 rather than the Windows 11 / RX 7600 / Python 3.13.14 setup used in M0–M7d (same pinned model digest and package freeze; all four M8 arms ran interleaved on the same machine with `0/110` M8b noise).
6. **Unclean Runs & Decoding Audits (`R-32`):** Seventeen runs hit `step_limit` with no stored oracle verdict (bounded in Section 7.3–7.4); `think=false` residual reasoning tokens and truncation at `1024` output tokens were not audited separately.
7. **Small Benign Sample ($n=9$):** Even with `0/9` benign disagreements, the exact one-sided 95% lower bound (`-0.386`) cannot statistically confirm benign non-inferiority within 10 pp.
8. **Unverified Remote CI (`BLK-003`):** All tests, strict mypy, `tools/ruff_stdin.py`, and security-core mutation checks pass locally, while GitHub Actions CI has not yet been verified on a pushed branch.

---

## 10. Conclusion

We designed, verified, and evaluated **AgentGuard v3.1** in a pre-registered factorial study (`B0`, `B1`, `B2`, `P1`) on the frozen test split of AgentDojo v1.2.2 banking with local `qwen3.5:9b`. Deterministic, intent-bound capability enforcement (`B2`) robustly reduced executed unauthorized actions from `31/99` (`31.3%`) to `2/94` (`2.1%`, $p = 1.19 \times 10^{-7}$, robust to cluster sign test, two-way bootstrap, leave-one-cluster-out, and worst-case unclean bounds) while preserving `100%` of clean utility under attack. In contrast, layering a coarse heuristic context analyzer (`P1`) closed the two wildcard-policy escapes (`0/93`, $p = 0.50$) only at the severe cost of losing `10` legitimate tasks under attack (`-13.3` pp valid / `-17.5` pp strict, $p = 0.00195$) and collapsing to identical trajectories with detector-only `B1`. Future work should test argument-scoped provenance detectors restricted to wildcard parameters, evaluate automated policy synthesis without oracle knowledge, and expand across additional suites and qualified models.

---

## 11. References

*(Every entry below was verified against arXiv metadata, ACL Anthology, or official pages in `docs/research/related-work-matrix.md`; no DOIs or unverified publication details are added.)*

1. An et al. (2025). *IPIGuard: A Novel Tool Dependency Graph-Based Defense Against Indirect Prompt Injection in LLM Agents*. EMNLP 2025. arXiv:2508.15310.
2. Betser et al. (2026). *AgenTRIM: Tool Risk Mitigation for Agentic AI*. EMNLP 2026 Findings. arXiv:2601.12449.
3. Beurer-Kellner et al. (2025). *Design Patterns for Securing LLM Agents against Prompt Injections*. arXiv preprint, arXiv:2506.08837.
4. Chen et al. (2024). *StruQ: Defending Against Prompt Injection with Structured Queries*. USENIX Security 2025. arXiv:2402.06363.
5. Chen et al. (2024). *SecAlign: Defending Against Prompt Injection with Preference Optimization*. ACM CCS 2025. arXiv:2410.05451.
6. Chen et al. (2025). *ShieldAgent: Shielding Agents via Verifiable Safety Policy Reasoning*. arXiv preprint, arXiv:2503.22738.
7. Chennabasappa et al. (2025). *LlamaFirewall: An open source guardrail system for building secure AI agents*. arXiv preprint, arXiv:2505.03574.
8. Costa et al. (2025). *Securing AI Agents with Information-Flow Control* (FIDES). arXiv preprint, arXiv:2505.23643.
9. Debenedetti et al. (2024). *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*. NeurIPS 2024 Datasets and Benchmarks Track. arXiv:2406.13352.
10. Debenedetti et al. (2025). *Defeating Prompt Injections by Design* (CaMeL). arXiv preprint, arXiv:2503.18813.
11. Greshake et al. (2023). *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. arXiv:2302.12173.
12. Hines et al. (2024). *Defending Against Indirect Prompt Injection Attacks With Spotlighting*. arXiv preprint, arXiv:2403.14720.
13. Ji et al. (2026). *Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework* (MAC-Agents). arXiv preprint, arXiv:2601.11893.
14. Jia et al. (2024). *The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents*. ACL 2025. arXiv:2412.16682.
15. Li et al. (2025). *ACE: A Security Architecture for LLM-Integrated App Systems*. NDSS 2026. arXiv:2504.20984.
16. Li et al. (2025). *DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents*. NeurIPS 2025. arXiv:2506.12104.
17. Liu et al. (2023). *Formalizing and Benchmarking Prompt Injection Attacks and Defenses*. USENIX Security 2024. arXiv:2310.12815.
18. Liu et al. (2025). *DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks*. IEEE S&P 2025. arXiv:2504.11358.
19. Shi et al. (2025). *Progent: Securing AI Agents with Privilege Control*. arXiv preprint, arXiv:2504.11703.
20. Tsai et al. (2025). *Contextual Agent Security: A Policy for Every Purpose* (Conseca). HotOS 2025. arXiv:2501.17070.
21. Wang et al. (2025). *AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents*. ICSE 2026. arXiv:2503.18666.
22. Wang (P.) et al. (2025). *AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection*. arXiv preprint, arXiv:2508.01249.
23. Willison, S. (2023). *The Dual LLM pattern for building AI assistants that can resist prompt injection*. Blog post, https://simonwillison.net/2023/Apr/25/dual-llm-pattern/.
24. Wu et al. (2025). *IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems*. NDSS 2025. arXiv:2403.04960.
25. Xiang et al. (2024). *GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning*. ICML 2025. arXiv:2406.09187.
26. Zhan et al. (2024). *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents*. Findings of ACL 2024. arXiv:2403.02691.
27. Zhong et al. (2025). *RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage*. arXiv preprint, arXiv:2502.08966.
28. Zhu et al. (2025). *MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents*. ICML 2025. arXiv:2502.05174.
29. Zhu (J.) et al. (2025). *MiniScope: Authorizing Agents with Least-Privilege Permissions*. arXiv preprint, arXiv:2512.11147.
30. Zhu (G.) et al. (2026). *Intent-Governed Tool Authorization for AI Agents* (IGTA). arXiv preprint, arXiv:2606.22916.
