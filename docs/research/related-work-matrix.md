# Related Work and Research-Gap Matrix (draft for approval)

Verification: bibliographic fields were checked on 2026-11-18 against arXiv metadata and abstract pages,
ACL Anthology, PyPI, GitHub, and Hugging Face. **Venue** is listed only where confirmed; otherwise
"arXiv preprint". "AgentDojo" = Y if the abstract or full text names AgentDojo as an evaluation benchmark;
"n/a-abs" = not stated in the abstract and full text not checked (treat as unverified, not as No).
Reported numbers from papers are **not** reproduced here except where read directly from the paper (LlamaFirewall).

## 1. Verified sources

| Key | Title | First author et al. | Year | Venue | ID / URL | Category | AgentDojo |
|---|---|---|---|---|---|---|---|
| AgentDojo | AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents | Debenedetti | 2024 | NeurIPS 2024 D&B | arXiv:2406.13352 | Benchmark | — |
| InjecAgent | InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents | Zhan | 2024 | Findings of ACL 2024 | arXiv:2403.02691 | Benchmark | — |
| Greshake | Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection | Greshake | 2023 | venue unverified | arXiv:2302.12173 | Attack taxonomy | — |
| Liu-Formal | Formalizing and Benchmarking Prompt Injection Attacks and Defenses | Liu | 2023 | USENIX Security 2024 | arXiv:2310.12815 | Formalization + benchmark | n/a-abs |
| CaMeL | Defeating Prompt Injections by Design | Debenedetti | 2025 | arXiv preprint | arXiv:2503.18813 | Control/data-flow separation + capabilities | Y |
| Progent | Progent: Securing AI Agents with Privilege Control (v1: "…Programmable Privilege Control for LLM Agents") | Shi | 2025 | arXiv preprint | arXiv:2504.11703 | Privilege policy DSL, deterministic enforcement | Y |
| FIDES | Securing AI Agents with Information-Flow Control | Costa | 2025 | arXiv preprint | arXiv:2505.23643 | IFC labels | Y |
| DesignPatterns | Design Patterns for Securing LLM Agents against Prompt Injections | Beurer-Kellner | 2025 | arXiv preprint | arXiv:2506.08837 | Architectural patterns | n/a-abs |
| DualLLM | The Dual LLM pattern for building AI assistants that can resist prompt injection | Willison | 2023 | Blog | simonwillison.net/2023/Apr/25/dual-llm-pattern/ | Architectural pattern | — |
| IsolateGPT | IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems | Wu | 2025 | NDSS 2025 | arXiv:2403.04960 | Isolation | n/a-abs |
| ACE | ACE: A Security Architecture for LLM-Integrated App Systems | Li | 2025 | NDSS 2026 | arXiv:2504.20984 | Trusted abstract plan + IFC + capability barriers | No (InjecAgent, ASB) |
| RTBAS | RTBAS: Defending LLM Agents Against Prompt Injection and Privacy Leakage | Zhong | 2025 | arXiv preprint | arXiv:2502.08966 | IFC on tool calls | Y |
| Spotlighting | Defending Against Indirect Prompt Injection Attacks With Spotlighting | Hines | 2024 | arXiv preprint | arXiv:2403.14720 | Prompt marking | shipped as AgentDojo baseline |
| StruQ | StruQ: Defending Against Prompt Injection with Structured Queries | Chen | 2024 | USENIX Security 2025 | arXiv:2402.06363 | Training | n/a-abs |
| SecAlign | SecAlign: Defending Against Prompt Injection with Preference Optimization | Chen | 2024 | ACM CCS 2025 | arXiv:2410.05451 | Training | n/a-abs |
| DataSentinel | DataSentinel: A Game-Theoretic Detection of Prompt Injection Attacks | Liu | 2025 | IEEE S&P 2025 | arXiv:2504.11358 | Detector | n/a-abs |
| ProtectAI | protectai/deberta-v3-base-prompt-injection-v2 (model card; project archived) | ProtectAI | 2024 | HF model card | huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 | Detector | (AgentDojo's PI detector is DeBERTa-based) |
| PromptArmor | PromptArmor (full title not yet recorded — verify before citing) | Shi | 2025 | arXiv preprint | arXiv:2507.15219 | Detector | Y |
| MELON | MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents | Zhu | 2025 | ICML 2025 | arXiv:2502.05174 | Detector (masked re-execution) | Y |
| TaskShield | The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents | Jia | 2024 | ACL 2025 | arXiv:2412.16682 | Task alignment (LLM-checked) | Y |
| LlamaFirewall | LlamaFirewall: An open source guardrail system for building secure AI agents | Chennabasappa | 2025 | arXiv preprint | arXiv:2505.03574 | Detector (PromptGuard 2) + alignment auditor | Y (full text §4) |
| AgentSpec | AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents | Wang | 2025 | ICSE 2026 | arXiv:2503.18666 | Runtime rule DSL | n/a-abs |
| GuardAgent | GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning | Xiang | 2024 | ICML 2025 | arXiv:2406.09187 | Guard agent | n/a-abs |
| ShieldAgent | ShieldAgent: Shielding Agents via Verifiable Safety Policy Reasoning | Chen | 2025 | arXiv preprint | arXiv:2503.22738 | Verifiable policy reasoning | n/a-abs |
| Conseca | Contextual Agent Security: A Policy for Every Purpose | Tsai | 2025 | HotOS 2025 | arXiv:2501.17070 | Context-specific policy generation | n/a-abs |
| **IGTA** | **Intent-Governed Tool Authorization for AI Agents** | Zhu (G.) | 2026 | arXiv preprint (v4) | arXiv:2606.22916 | **Intent binding + policy enforcement** | n/a-abs |
| **DRIFT** | **DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents** | Li | 2025 | NeurIPS 2025 | arXiv:2506.12104 | **Intent-derived policy + injection detection/isolation** | Y |
| IPIGuard | IPIGuard: A Novel Tool Dependency Graph-Based Defense Against Indirect Prompt Injection in LLM Agents | An | 2025 | EMNLP 2025 | arXiv:2508.15310 | Pre-planned tool graph (task binding) | Y |
| AgentArmor | AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection | Wang (P.) | 2025 | arXiv preprint | arXiv:2508.01249 | Program analysis + type-system policy | Y |
| MiniScope | MiniScope: Authorizing Agents with Least-Privilege Permissions | Zhu (J.) | 2025 | arXiv preprint | arXiv:2512.11147 | Task-scoped least privilege | n/a-abs |
| AgenTRIM | AgenTRIM: Tool Risk Mitigation for Agentic AI | Betser | 2026 | EMNLP 2026 Findings | arXiv:2601.12449 | Least-privilege tool filtering + call validation | Y |
| MAC-Agents | Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework | Ji | 2026 | arXiv preprint | arXiv:2601.11893 | Attribute-based MAC over info-flow graph | n/a-abs |

AgentDojo package: PyPI `agentdojo` 0.1.35 (2025-10-27), `requires_python >=3.10`, MIT license. Built-in
defenses: `tool_filter` (OpenAI-only), `transformers_pi_detector` (DeBERTa, inspects tool outputs),
`spotlighting_with_delimiting`, `repeat_user_prompt`.

## 2. Research-gap matrix

Columns: what each approach does. ✔ = core feature, ◐ = partial/implicit, ✘ = not a feature (per abstract-level
reading; to be refined from full texts before the paper is written).

| Approach | Deterministic tool-call policy | Bound to trusted user task/intent | Untrusted-content detector | Detector + policy combined | Factorial ablation (detector-only vs policy-only vs both, same harness) | Local small open models as agent |
|---|---|---|---|---|---|---|
| Progent | ✔ | ◐ (LLM-generated per task) | ✘ | ✘ | ✘ | unverified |
| CaMeL | ✔ (capabilities on values) | ✔ (plan from trusted query) | ✘ | ✘ | ✘ | unverified |
| FIDES / RTBAS / ACE | ✔ (IFC) | ◐ | ◐ (RTBAS screeners) | ◐ | ✘ | unverified |
| Task Shield | ✘ (LLM judgment) | ✔ | ◐ | ✘ | ✘ | unverified |
| MELON / DataSentinel / PromptArmor / ProtectAI | ✘ | ✘/◐ | ✔ | ✘ | ✘ | unverified |
| LlamaFirewall | ✘ | ◐ (AlignmentCheck) | ✔ | ✔ (layered guardrails) | ◐ (reports each scanner and combined) | unverified |
| **DRIFT** | ✔ | ✔ (planner from query) | ✔ (isolator) | ✔ | ◐ (ablations reported; details unverified) | unverified |
| **IGTA** | ✔ | ✔ (intent certificates) | ✘ | ✘ | ✘ | unverified |
| MiniScope / AgenTRIM / MAC-Agents | ✔ | ✔/◐ | ✘ | ✘ | ✘ | unverified |
| **AgentGuard (proposed)** | ✔ | ✔ (human-authored from task text) | ✔ (transparent heuristics) | ✔ | ✔ (B0/B1/B2/P1, paired) | ✔ (≤ 8 GiB VRAM) |

## 3. Novelty claims — status

| Claim | Status | Basis |
|---|---|---|
| "Intent-bound tool authorization is a new mechanism" | **Unsupported** | IGTA (2606.22916) explicitly proposes intent-governed tool authorization; CaMeL, Progent, DRIFT, MiniScope bind permissions to the user task |
| "Combining a context detector with permission enforcement is new" | **Unsupported** | DRIFT combines intent-derived rules with injection isolation; LlamaFirewall layers detectors with alignment checks |
| "A controlled, paired factorial evaluation isolating the incremental contribution of a detector on top of deterministic task-scoped permissions (RQ2), with an oracle that separates attempted / denied / executed / achieved" | **Unverified (plausible gap)** | No source in this review was confirmed to report this exact paired attribution; must be checked against full texts of DRIFT, LlamaFirewall, Progent, IGTA before claiming |
| "Evaluation of these defenses with small local open-weight models on consumer hardware" | **Unverified (plausible gap)** | Model choice in prior work not checked |
| "Transparent, non-LLM heuristic analyzer with zero extra model calls" | **Unverified**; likely incremental | Cost advantage vs LLM-based analyzers (Task Shield, MELON, PromptArmor) is measurable in RQ5 |

**Recommended framing (D-008):** an empirical, reproducible attribution study — *how much of the protection
comes from task-scoped permissions vs context analysis, at what utility and cost* — rather than a new
defense mechanism. Full-text checks of DRIFT, IGTA, LlamaFirewall and Progent are required before the paper
(M9) makes any novelty statement.

## 4. Unverified items
- Greshake et al. venue (AISec 2023) not confirmed.
- AgentDojo usage for entries marked n/a-abs.
- Venues for preprints listed as "arXiv preprint".
- Reported numbers from other papers (except LlamaFirewall §4 figures, not reproduced here) are not used.
