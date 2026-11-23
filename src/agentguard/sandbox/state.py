"""Isolated in-memory sandbox state with snapshot, commit and structural diff.

This module (like the rest of ``sandbox/``) performs no I/O whatsoever (SEC-015, REQ-SBX-1).
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr

from agentguard.errors import ConfigError


class Transaction(BaseModel):
    recipient: str
    amount: Decimal
    subject: str


class Email(BaseModel):
    to: str
    subject: str
    body: str


class SandboxState(BaseModel):
    """All side effects of mock tools land here and nowhere else."""

    files: dict[str, str] = Field(default_factory=dict)
    balance: Decimal = Decimal("1000.00")
    transactions: list[Transaction] = Field(default_factory=list)
    outbox: list[Email] = Field(default_factory=list)

    _sandbox_id: str = PrivateAttr(default_factory=lambda: uuid.uuid4().hex)
    _bound_run: str | None = PrivateAttr(default=None)

    @property
    def sandbox_id(self) -> str:
        return self._sandbox_id

    def bind_run(self, run_id: str) -> None:
        """A sandbox belongs to exactly one run; reuse across runs is refused (SEC-015)."""
        if self._bound_run is not None and self._bound_run != run_id:
            raise ConfigError("sandbox state is already bound to another run")
        self._bound_run = run_id

    def snapshot(self) -> SandboxState:
        """Deep, detached copy for pre/post comparison and for atomic execution."""
        return self.model_copy(deep=True)

    def replace_with(self, other: SandboxState) -> None:
        """Commit another state's content into this object (used for atomic commit)."""
        self.files = dict(other.files)
        self.balance = other.balance
        self.transactions = [t.model_copy(deep=True) for t in other.transactions]
        self.outbox = [e.model_copy(deep=True) for e in other.outbox]

    def content(self) -> dict[str, Any]:
        """Canonical, identity-free content used for equality and diffing."""
        return self.model_dump(mode="json")


def state_diff(pre: SandboxState, post: SandboxState) -> dict[str, tuple[Any, Any]]:
    """Top-level fields whose content differs (empty dict means no observable change)."""
    a, b = pre.content(), post.content()
    return {k: (a[k], b[k]) for k in a if a[k] != b[k]}
