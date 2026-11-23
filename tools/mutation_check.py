"""Manual mutation check for the security core.

Each mutation weakens one security-relevant line; the test suite must FAIL for it to count as
"killed". A surviving mutation means a security behaviour is not covered by tests (QG-02).
Source files are restored in ``finally`` and verified byte-identical afterwards.

Usage: python tools/mutation_check.py
"""

# ruff: noqa: E501  (mutation patterns are verbatim source lines)
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "agentguard"


@dataclass(frozen=True)
class Mutation:
    mid: str
    invariant: str
    file: str
    old: str
    new: str


MUTATIONS = [
    Mutation(
        "M01",
        "SEC-005/012 explicit deny wins",
        "policy/policy_engine.py",
        'if cap.effect == "deny" and self._constraints_hold(cap, call):',
        "if False and self._constraints_hold(cap, call):",
    ),
    Mutation(
        "M02",
        "SEC-005 security args must be constrained",
        "policy/policy_engine.py",
        "if security_params <= set(c.constraints) and self._constraints_hold(c, call)",
        "if self._constraints_hold(c, call)",
    ),
    Mutation(
        "M03",
        "SEC-006 policy deny is final in P1",
        "defense/authorization_gateway.py",
        "if pv.verdict is Verdict.DENY:  # policy denial is final (SEC-006)",
        "if False:",
    ),
    Mutation(
        "M04",
        "SEC-013 analyzer failure must deny",
        "defense/authorization_gateway.py",
        "        if err is not None:\n            d = self._decide(task_id, call, Verdict.DENY, (err,), cap_id)",
        "        if False:\n            d = self._decide(task_id, call, Verdict.DENY, (err,), cap_id)",
    ),
    Mutation(
        "M05",
        "SEC-002 decision MAC verified",
        "defense/authorization_gateway.py",
        "if not hmac.compare_digest(expected, decision.mac):",
        "if False:",
    ),
    Mutation(
        "M06",
        "SEC-002 decision is single-use",
        "defense/authorization_gateway.py",
        "if decision.decision_id in self._consumed:",
        "if False:",
    ),
    Mutation(
        "M07",
        "SEC-007 decision bound to call/task",
        "defense/authorization_gateway.py",
        "if decision.call_hash != call.call_hash or decision.task_id != call.task_id:",
        "if False:",
    ),
    Mutation(
        "M08",
        "SEC-003 atomic execution",
        "sandbox/executor.py",
        "working = self._state.snapshot()",
        "working = self._state",
    ),
    Mutation(
        "M09",
        "SEC-011 no silent clamp above root",
        "normalize.py",
        '            if not parts:\n                raise NormalizationError("path escapes the root")\n            parts.pop()',
        "            if parts:\n                parts.pop()",
    ),
    Mutation(
        "M10",
        "SEC-011 segment-aware prefix",
        "normalize.py",
        'return path == prefix or path.startswith(prefix + "/")',
        "return path.startswith(prefix)",
    ),
    Mutation(
        "M11",
        "SEC-010 hash covers payload",
        "storage/audit_logger.py",
        "canonical_json([seq, ts, kind, task_id, payload, prev])",
        "canonical_json([seq, ts, kind, task_id, prev])",
    ),
    Mutation(
        "M12",
        "SEC-013 unexpected validation error fails closed",
        "defense/authorization_gateway.py",
        "except Exception as exc:  # InvalidCallError, but also any unexpected failure: fail closed",
        "except InvalidCallError as exc:",
    ),
    Mutation(
        "M13",
        "SEC-008 grant needs trusted token",
        "policy/capability_store.py",
        "if not isinstance(token, str) or not self._verify(self._task_id, capability, token):",
        "if False:",
    ),
    Mutation(
        "M14",
        "SEC-014 no hidden detector in B0/B2",
        "defense/authorization_gateway.py",
        "if not needs_analyzer and analyzer is not None:",
        "if False:",
    ),
    Mutation(
        "M15",
        "SEC-008 task lifecycle needs trusted channel",
        "defense/authorization_gateway.py",
        "if channel is not self._channel:",
        "if False:",
    ),
    Mutation(
        "M16",
        "SEC-015 sandbox bound to one run",
        "sandbox/executor.py",
        "state.bind_run(run_id)  # refuses a sandbox that already belongs to another run",
        "pass",
    ),
    Mutation(
        "M17",
        "SEC-012 call budget enforced",
        "policy/policy_engine.py",
        "if cap.max_calls is None or usage.get(cap.cap_id, 0) < cap.max_calls:",
        "if True:",
    ),
    Mutation(
        "M18",
        "SEC-004 unknown arguments rejected",
        "agent/tool_registry.py",
        "        if unknown:\n",
        "        if False:\n",
    ),
    Mutation(
        "M19",
        "SEC-001 only task-active calls decided",
        "defense/authorization_gateway.py",
        "if rec is None or rec.closed:\n            return AuthorizationResult(",
        "if rec is None:\n            return AuthorizationResult(",
    ),
    Mutation(
        "M21",
        "SEC-011 IBAN must be ASCII (RF-002)",
        "normalize.py",
        "    if not raw.isascii():  # upper() can expand characters (e.g. sharp s -> SS): reject, never guess",
        "    if False:",
    ),
    Mutation(
        "M22",
        "SEC-011 email must be ASCII (RF-002)",
        "normalize.py",
        "    if not raw.isascii():  # lower() can also change length/shape for some Unicode letters",
        "    if False:",
    ),
    Mutation(
        "M23",
        "REQ-ORC-4 model timeout is not a success",
        "agent/orchestrator.py",
        "                return finish(RunStatus.MODEL_TIMEOUT)",
        "                return finish(RunStatus.COMPLETED)",
    ),
    Mutation(
        "M24",
        "REQ-AGT-2 step limit enforced",
        "agent/orchestrator.py",
        "            if steps >= lim.max_steps:",
        "            if False:",
    ),
    Mutation(
        "M25",
        "S-7 analyzer context built from tool results",
        "agent/orchestrator.py",
        "            context.append(ContextItem(text=text, source=res.source))  # untrusted by construction",
        "            pass",
    ),
    Mutation(
        "M26",
        "R-08 context overflow detected",
        "agent/model_adapter.py",
        "        if n_in + n_out >= int(self._cfg.num_ctx * CONTEXT_FILL_LIMIT):",
        "        if False:",
    ),
    Mutation(
        "M27",
        "REQ-GOV-1 only loopback model servers",
        "agent/model_adapter.py",
        '        if parsed.scheme != "http" or (parsed.hostname or "") not in LOOPBACK_HOSTS:',
        "        if False:",
    ),
    Mutation(
        "M28",
        "SEC-007 task closed after every run",
        "agent/orchestrator.py",
        "            self._stack.close_task(task_id)",
        "            pass",
    ),
    Mutation(
        "M29",
        "REQ-AGT-2 token limit enforced",
        "agent/orchestrator.py",
        "            if n_in + n_out >= lim.max_total_tokens:",
        "            if False:",
    ),
    Mutation(
        "M30",
        "D-012 wildcard only when explicitly written",
        "policy/policy_engine.py",
        "    if constraint.any_value:\n        return True",
        "    if constraint.any_value:\n        return False",
    ),
    Mutation(
        "M31",
        "benign utility rejects out-of-scope state changes",
        "evaluation/benign_tasks.py",
        "    return set(state_diff(pre, post)) <= task.allowed_changes",
        "    return True",
    ),
    Mutation(
        "M32",
        "benign utility requires a clean completion",
        "evaluation/benign_tasks.py",
        "    if not completed:\n        return False",
        "    if False:\n        return False",
    ),
    Mutation(
        "M33",
        "REQ-CA-1 threshold comparison is inclusive",
        "defense/context_analyzer.py",
        "score >= cfg.threshold - 1e-9",
        "score > cfg.threshold",
    ),
    Mutation(
        "M34",
        "analyzer ignores instruction content for read-only calls",
        "defense/context_analyzer.py",
        "side_effects = 1.0 if (spec is not None and spec.protected) else 0.0",
        "side_effects = 1.0",
    ),
    Mutation(
        "M35",
        "S1 provenance requires value absent from the prompt",
        "defense/context_analyzer.py",
        "if value and value not in prompt_sq and any(value in t for t in item_sq):",
        "if value and any(value in t for t in item_sq):",
    ),
    Mutation(
        "M36",
        "analyzer input size bounded",
        "defense/context_analyzer.py",
        "        body = text[:MAX_ITEM_CHARS]",
        "        body = text",
    ),
    Mutation(
        "M37",
        "REQ-ORC-4 unclean attack runs excluded from ASR",
        "evaluation/metrics.py",
        "    a_clean = [r for r in attack if r.clean]",
        "    a_clean = list(attack)",
    ),
    Mutation(
        "M38",
        "paired analysis drops unclean pairs",
        "evaluation/statistics.py",
        "if other is None or (only_clean and not (r.clean and other.clean)):",
        "if other is None:",
    ),
    Mutation(
        "M39",
        "exact McNemar uses the smaller tail",
        "evaluation/statistics.py",
        "    k = min(b, c)",
        "    k = max(b, c)",
    ),
    Mutation(
        "M40",
        "REQ-EVL-5 manifest tampering detected",
        "evaluation/manifest.py",
        "        if not self.content_hash or self.content_hash != self.compute_hash():",
        "        if not self.content_hash:",
    ),
    Mutation(
        "M41",
        "config must match the frozen manifest hash",
        "evaluation/config.py",
        "        if manifest.content_hash != self.manifest_hash:",
        "        if False:",
    ),
    Mutation(
        "M42",
        "splits are decided per cluster",
        "evaluation/manifest.py",
        "split=assign_split(cl, seed),",
        "split=assign_split(cid, seed),",
    ),
    Mutation(
        "M20",
        "SEC-009 untrusted-only context items",
        "policy/schemas.py",
        "if v is not Trust.UNTRUSTED:",
        "if False:",
    ),
]


def run_tests() -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-x",
            "-p",
            "no:cacheprovider",
            "--no-header",
            "tests",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    failed = [
        ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED") or ln.startswith("ERROR")
    ]
    return proc.returncode, (failed[0] if failed else proc.stdout.strip().splitlines()[-1])


def main() -> int:
    rc, summary = run_tests()
    if rc != 0:
        print(f"baseline suite is not green: {summary}")
        return 2
    survivors = 0
    for m in MUTATIONS:
        path = SRC / m.file
        original = path.read_bytes()
        text = original.decode("utf-8").replace("\r\n", "\n")  # patterns are LF; file may be CRLF
        if text.count(m.old) != 1:
            print(f"{m.mid}  INVALID (pattern found {text.count(m.old)}x) {m.file}")
            survivors += 1
            continue
        try:
            path.write_bytes(text.replace(m.old, m.new).encode("utf-8"))
            rc, summary = run_tests()
        finally:
            path.write_bytes(original)
        assert path.read_bytes() == original  # noqa: S101 - tooling self-check
        status = "killed  " if rc != 0 else "SURVIVED"
        survivors += rc == 0
        print(f"{m.mid}  {status}  {m.invariant:<46} {summary[:90] if rc else ''}")
    print(f"\n{len(MUTATIONS) - survivors}/{len(MUTATIONS)} mutations killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
