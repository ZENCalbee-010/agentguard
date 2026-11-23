"""Structural guarantees (import boundaries) and a randomized no-side-effect property test."""

from __future__ import annotations

import ast
import random
from pathlib import Path

import pytest

from agentguard.errors import UnauthorizedExecution
from agentguard.policy.schemas import GatewayMode, Verdict
from agentguard.sandbox.state import state_diff
from agentguard.testing.builders import allow, at_most, eq, prefix
from agentguard.testing.doubles import FixedAnalyzer
from conftest import ATTACKER_IBAN, BILL_IBAN

pytestmark = pytest.mark.security
SRC = Path(__file__).resolve().parents[2] / "src" / "agentguard"


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _violations(files: list[Path], forbidden: tuple[str, ...]) -> list[str]:
    return [
        f"{f.name}: {m}"
        for f in files
        for m in _imports(f)
        if any(m == p or m.startswith(p + ".") for p in forbidden)
    ]


def test_ac_m3_17_oracle_does_not_import_defense_policy_agent_or_storage() -> None:  # REQ-ORC-2
    oracle = SRC / "evaluation" / "oracle.py"
    forbidden = (
        "agentguard.defense",
        "agentguard.policy",
        "agentguard.agent",
        "agentguard.storage",
        "agentguard.stack",
    )
    assert _violations([oracle], forbidden) == []


def test_ac_m3_17_sandbox_has_no_network_process_or_file_capabilities() -> None:  # REQ-SBX-1
    forbidden = (
        "socket", "smtplib", "http", "urllib", "ftplib", "requests", "httpx", "aiohttp",
        "subprocess", "os", "shutil", "pathlib", "ssl", "asyncio", "sqlite3", "ctypes",
    )  # fmt: skip
    files = sorted((SRC / "sandbox").glob("*.py"))
    assert files
    assert _violations(files, forbidden) == []


def test_import_boundary_check_actually_detects_violations(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("import socket\nfrom agentguard.defense.x import y\n", encoding="utf-8")
    assert len(_violations([bad], ("socket", "agentguard.defense"))) == 2


@pytest.mark.parametrize("mode", [GatewayMode.B2, GatewayMode.P1])
def test_ac_m3_16_denied_calls_never_change_state(make, mode) -> None:  # type: ignore[no-untyped-def]
    """Randomized: whatever is proposed, a DENY must leave the sandbox identical."""
    rng = random.Random(20261118)
    an = FixedAnalyzer(Verdict.ALLOW) if mode is GatewayMode.P1 else None
    stack, task = make(
        mode,
        allow("read_file", path=prefix("/docs")),
        allow("send_money", recipient_iban=eq(BILL_IBAN), amount=at_most(50), max_calls=3),
        analyzer=an,
    )
    tools = [
        "read_file",
        "send_money",
        "send_email",
        "write_file",
        "delete_file",
        "get_balance",
        "bogus",
    ]
    values: list[object] = [
        "/docs/a.txt", "/docs/../secrets/key.txt", "/secrets/key.txt", "\\docs\\..\\x", "%2e%2e", "",
        BILL_IBAN, ATTACKER_IBAN, "eve@evil.com", 1, 49.99, 50.01, -1, 0, "NaN", "1e400", None, True,
        [1], {"a": 1}, "x" * 50, "a\x00b",
    ]  # fmt: skip
    arg_names = ["path", "recipient_iban", "amount", "subject", "to", "body", "content", "extra"]
    valid_templates: list[dict[str, object]] = [
        {"tool": "read_file", "args": {"path": "/docs/a.txt"}},
        {
            "tool": "send_money",
            "args": {"recipient_iban": BILL_IBAN, "amount": 10, "subject": "s"},
        },
    ]

    def propose() -> dict[str, object]:
        roll = rng.random()
        if roll < 0.3:  # fully random garbage
            return {
                "tool": rng.choice(tools),
                "args": {k: rng.choice(values) for k in rng.sample(arg_names, rng.randint(0, 4))},
            }
        base = rng.choice(valid_templates)
        args = dict(base["args"])  # type: ignore[call-overload]
        if roll < 0.5:  # untouched valid call
            return {"tool": base["tool"], "args": args}
        mutation = rng.choice(["replace", "drop", "add"])  # one random defect
        if mutation == "replace" and args:
            args[rng.choice(sorted(args))] = rng.choice(values)
        elif mutation == "drop" and args:
            del args[rng.choice(sorted(args))]
        else:
            args[rng.choice(arg_names)] = rng.choice(values)
        return {"tool": base["tool"], "args": args}

    n_denied = n_allowed = 0
    for _ in range(600):
        proposed = propose()
        before = stack.state.snapshot()
        res = stack.gateway.authorize(task, proposed)
        if res.decision.allowed:
            n_allowed += 1
            assert res.call is not None
            stack.executor.execute(res.call, res.decision)
            continue
        n_denied += 1
        if res.call is not None:
            with pytest.raises(UnauthorizedExecution):
                stack.executor.execute(res.call, res.decision)
        assert state_diff(before, stack.state) == {}
    assert n_denied > 150 and n_allowed > 50  # the generator really exercises both outcomes
    assert all(t.recipient == BILL_IBAN and t.amount <= 50 for t in stack.state.transactions)
    assert len(stack.state.transactions) <= 3 and not stack.state.outbox
    assert stack.audit.verify_chain()
