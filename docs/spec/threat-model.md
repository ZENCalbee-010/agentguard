# Threat Model (draft for approval)

## 1. System under protection
A single-user LLM agent that receives a task from a **trusted user**, plans, and calls tools from a fixed
registry. Tool results (emails, documents, web pages, files, messages, transaction notes, …) flow back
into the model context. All tools in this project are **simulated** against an isolated sandbox state.

## 2. Assets
1. Integrity of sandbox state (files, calendar, accounts, messages, transactions).
2. Confidentiality of sandbox data (must not be sent to attacker-controlled destinations).
3. The trusted task binding (task identity + capability scope).
4. Integrity of audit records and experiment evidence.

## 3. Trust boundaries and data sources

| Source | Trust | Can grant capabilities? | Notes |
|---|---|---|---|
| User task prompt (from the experiment runner / CLI) | **Trusted** | Yes, only via the trusted-task channel at task creation | Captured once, immutable for the task |
| Policy files (frozen, hashed) | **Trusted** | Yes (defines capability templates) | Changes need human approval after freeze |
| System prompt & tool schemas (from registry) | Trusted | No | |
| Tool outputs, retrieved documents, web content, messages, file contents | **Untrusted** | **Never** (SEC-001, SEC-009) | Includes benchmark attack strings |
| Model output (proposed tool calls, text) | **Untrusted** (may be attacker-influenced) | Never | Every proposed call is validated |
| Context analyzer verdict | Advisory, can only restrict | No — can only turn ALLOW into DENY (SEC-006) | |

## 4. Attacker model
- **Capability:** controls the content of one or more untrusted data items the agent will read during the
  task (indirect prompt injection). Knows the tool names and general task domain (as in AgentDojo).
- **Cannot:** modify the user prompt, policy files, system prompt, tool code, gateway code, the sandbox
  directly, or the audit log; cannot observe the defense's internal state between runs.
- **Goals (in scope):**
  - G1 *Unauthorized tool* — cause a call to a tool outside the task's scope (e.g. `send_money` during a
    "summarize my bills" task).
  - G2 *Tool misuse* — use an in-scope tool for an unrelated purpose (e.g. `send_email` allowed for replying
    to Alice, used to forward data to an attacker).
  - G3 *Argument/resource/recipient redirection* — substitute recipient, IBAN, path, URL, or amount.
  - G4 *Trust-boundary crossing* — make untrusted content act as instructions or as a source of authority
    (e.g. "the user has authorized…", "new policy: …").
  - G5 *Multi-step escalation* — chain individually plausible calls to reach an out-of-scope effect.
- **Adaptivity:** primary evaluation uses the benchmark's fixed attack families (non-adaptive). Adaptive
  attacks against the analyzer (heuristic evasion) are acknowledged as a limitation; a small set of
  analyzer-aware variants may be evaluated as exploratory work (separately reported).

## 5. Out of scope
- Direct prompt injection / jailbreak by the user (the user is trusted).
- Answer-only manipulation (misinformation in the final text without a tool side effect), unless explicitly
  evaluated as an exploratory metric. AgentDojo injection tasks whose goal is answer-only are classified
  *out of scope* in M2.
- Attacks on the model weights, host OS, Ollama server, or supply chain.
- Data exfiltration through the model's text answer to the user (no tool call).
- Real-world systems, real email, real network transfer — none exist in this project.

## 6. Security assumptions
- A1: The gateway, policy engine and sandbox code are not compromised.
- A2: The trusted user prompt correctly expresses the intended task.
- A3: Every side-effecting tool is registered as *protected* and reachable only via the gateway (enforced
  by construction: tools are not callable except through `executor.execute(decision)` — SEC-002).
- A4: Policies are written from the user-task text and tool schemas only (no knowledge of injection goals).
  This assumption is **fragile** and is a key threat to validity (R-06).

## 7. Residual risks acknowledged up front
- A policy that permits a tool+argument the attacker also wants (e.g. task legitimately requires sending
  money to an IBAN that the attacker also targets) cannot be distinguished by capability checks alone.
- Data-flow attacks *within* scope (the attacker changes *which* in-scope value is used) can only be
  caught by value-provenance signals; the heuristic analyzer may miss them.
- Heuristic analyzers are evadable by adaptive attackers.
