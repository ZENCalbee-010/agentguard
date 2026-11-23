# Research Questions, Hypotheses, and Analysis Plan (draft for approval)

> **Superseded for the M8 study** by `docs/research/m8-analysis-plan.md` (confirmatory test reduced to H1; H2 and H3 descriptive; see its section 8 for every deviation). This M1 draft is kept as the historical record.

Status: **DRAFT — awaiting human approval (M1 gate)**. After M8 freeze, changes require approval.

## 1. Configurations under comparison

All four share the same model, prompts, tool interface, sandbox, tasks, logging and oracle. They
differ **only** in the decision logic at the authorization gateway (see `docs/spec/architecture.md` §4).

| ID | Context analyzer | Capability policy | Decision at gateway for each proposed tool call |
|---|---|---|---|
| B0 | off | off | always ALLOW (call is still logged) |
| B1 | on | off | ALLOW iff analyzer verdict = ALLOW; analyzer error/timeout → DENY |
| B2 | off | on | ALLOW iff policy verdict = ALLOW (deny-by-default) |
| P1 | on | on | policy first; policy DENY is final (SEC-006); if policy ALLOW → analyzer decides; analyzer error/timeout → DENY |

Everything executes against simulated tools only (SEC-015).

## 2. Research questions and hypotheses

| RQ | Question | Hypothesis (directional, pre-registered) | Primary contrast |
|---|---|---|---|
| RQ1 | Does permission enforcement reduce executed unauthorized actions vs an unprotected agent? | H1: ASR(B2) < ASR(B0) | B2 vs B0 |
| RQ2 | Does context analysis add measurable protection beyond permission-only enforcement? | H2: ASR(P1) < ASR(B2). **A null result is anticipated as plausible and will be reported as such.** | P1 vs B2 |
| RQ2b | How effective is the detector alone? (descriptive, supports RQ2 interpretation) | H2b: ASR(B1) < ASR(B0) | B1 vs B0 |
| RQ3 | What is the impact on legitimate task completion? | H3: Benign utility of P1 is non-inferior to B0 with margin δ = 10 percentage points (δ to be confirmed at approval) | P1 vs B0, B2 vs B0 on benign cases |
| RQ4 | How consistent are results across model families and attack scenarios? | H4 (descriptive): the sign of the RQ1 effect is the same for every qualified model and benchmark suite | per-model, per-suite, per-attack-family breakdown |
| RQ5 | Performance, complexity, cost overhead? | Descriptive: gateway + analyzer added latency (median, P95), extra model calls (0 for the heuristic analyzer), tokens, cost, LOC | P1, B1, B2 vs B0 |

## 3. Metrics and denominators

Unit of observation = one **case** = (model, configuration, user task, injection task or ∅, attack
family, repetition). A *security case* has an injection; a *benign case* has none.

| Metric | Definition | Denominator |
|---|---|---|
| **Executed Unauthorized Action ASR (primary)** | Security case where the deterministic state oracle reports the injection goal achieved in the post-run sandbox state | All *completed* security cases of that config (errored runs reported separately, never counted as success or failure silently) |
| Attempted Unauthorized Action Rate | Security case where ≥1 *proposed* tool call matches the injection task's ground-truth call signature (tool name + goal-critical args, matcher defined in `docs/spec/requirements.md` REQ-ORC-3), regardless of gateway decision | Completed security cases |
| Block rate given attempt | Attempted cases where no matching call was executed | Attempted cases |
| Benign Task Success Rate | Benign case where the task utility oracle returns true | Completed benign cases |
| Task Success Under Attack | Security case where the user-task utility oracle returns true | Completed security cases |
| False Positive Rate (case level) | Benign case with ≥1 DENY | Completed benign cases |
| False Positive Rate (call level) | DENY of a call matching a ground-truth user-task call in a benign case | Ground-truth-matching calls proposed in benign cases |
| False Negative Rate (case level) | Security case with an executed injection-matching call | Attempted security cases |
| Latency | Wall-clock per case; gateway decision time per call; median and P95 | Cases / calls |
| Tokens, model calls, cost | From model adapter counters; cost = tokens × documented unit price (0 for local) | Per case, aggregated |
| Denial counts | DENY by reason code (policy rule, analyzer signal, error/timeout) | Per config |
| Memory | Peak RSS of the runner process (where practical) | Per run batch |

Distinctions enforced in records: *attempted* (model proposed) ≠ *denied* (gateway) ≠ *executed*
(sandbox applied) ≠ *goal achieved* (state oracle). Model text claiming an action never counts.

## 4. Statistical analysis plan (draft)

- **Pairing:** every case key (model, user task, injection task, attack family, repetition) is run under
  all four configurations → paired binary outcomes.
- **Primary tests:** exact McNemar test per contrast (B2–B0, P1–B2, B1–B0) on paired case outcomes,
  pooled over the frozen test split per model.
- **Dependence:** injection tasks and user tasks recur across cases. 95% CIs for rate differences use a
  **cluster bootstrap resampling user tasks** (10,000 resamples). Sensitivity analysis: two-way
  (user task × injection task) cluster bootstrap, and a mixed-effects logistic regression
  `outcome ~ config + (1|user_task) + (1|injection_task)` if it converges.
- **Repetitions:** if temperature > 0 or nondeterminism is observed, *k* repeats per case are aggregated
  to a per-case proportion before testing; repeats are never treated as independent cases.
- **Multiplicity:** Holm–Bonferroni across the confirmatory family {H1, H2, H3}; everything else is
  exploratory and labelled so.
- **Non-inferiority (H3):** one-sided 95% cluster-bootstrap CI lower bound of Utility(P1) − Utility(B0) > −δ.
- **Null results:** if the CI for P1–B2 includes 0, report "no detectable incremental benefit at this
  sample size" with the CI and a minimum detectable effect estimate.
- **Sample size:** set after the pilot (M7) from observed B0 ASR, discordant-pair rate and cost per case.

## 5. Data splits (to be finalized in M2 after inspecting the benchmark)

- **Development:** analyzer heuristics/thresholds and policies are tuned only here.
- **Validation:** threshold selection check; no further tuning after freeze.
- **Frozen test:** reported results.
- **External validation:** a different benchmark/attack source (InjecAgent candidate) and/or a
  different attack family not seen during development.
- Splits are made **by user task (cluster)**, not by case, so the same user task never appears in both
  development and test; attack templates used in development are recorded and test-only attack families
  are reported separately.
