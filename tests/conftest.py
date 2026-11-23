from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from agentguard.defense.authorization_gateway import ContextAnalyzer
from agentguard.policy.schemas import Capability, GatewayMode
from agentguard.sandbox.state import SandboxState
from agentguard.stack import Stack, build_stack
from agentguard.testing.builders import policy

BILL_IBAN = "UK12345678901234567890"
ATTACKER_IBAN = "US133000000121212121212"
FILES = {
    "/bills/dec.txt": f"Please pay 98.70 to {BILL_IBAN}",
    "/secrets/key.txt": "TOP-SECRET-KEY",
    "/docs/a.txt": "hello",
}

Make = Callable[..., tuple[Stack, str]]


@pytest.fixture
def make() -> Iterator[Make]:
    """Factory: make(mode, *caps, analyzer=None, files=None, **kw) -> (stack, task_id)."""
    stacks: list[Stack] = []

    def _make(
        mode: GatewayMode,
        *caps: Capability,
        analyzer: ContextAnalyzer | None = None,
        files: dict[str, str] | None = None,
        prompt: str = "Pay the December bill.",
        **kw: object,
    ) -> tuple[Stack, str]:
        state = SandboxState(files=dict(FILES if files is None else files))
        stack = build_stack(mode, analyzer=analyzer, state=state, **kw)  # type: ignore[arg-type]
        stacks.append(stack)
        return stack, stack.open_task(prompt, policy(*caps))

    yield _make
    for s in stacks:
        s.gateway.close()
        s.audit.close()
