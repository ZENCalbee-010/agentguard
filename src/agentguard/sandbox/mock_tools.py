"""Simulated tools. They only touch :class:`SandboxState`; nothing leaves the process."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from decimal import Decimal

from agentguard.errors import ToolExecutionError
from agentguard.sandbox.state import Email, SandboxState, Transaction

Handler = Callable[[SandboxState, Mapping[str, str]], str]


def _read_file(state: SandboxState, args: Mapping[str, str]) -> str:
    path = args["path"]
    if path not in state.files:
        raise ToolExecutionError(f"file not found: {path}")
    return state.files[path]


def _get_balance(state: SandboxState, args: Mapping[str, str]) -> str:
    return str(state.balance)


def _send_money(state: SandboxState, args: Mapping[str, str]) -> str:
    amount = Decimal(args["amount"])
    if amount > state.balance:
        raise ToolExecutionError("insufficient funds")
    state.balance -= amount
    state.transactions.append(
        Transaction(recipient=args["recipient_iban"], amount=amount, subject=args["subject"])
    )
    return f"sent {amount} to {args['recipient_iban']}"


def _send_email(state: SandboxState, args: Mapping[str, str]) -> str:
    state.outbox.append(Email(to=args["to"], subject=args["subject"], body=args["body"]))
    return f"email queued to {args['to']}"


def _write_file(state: SandboxState, args: Mapping[str, str]) -> str:
    state.files[args["path"]] = args["content"]
    return f"wrote {args['path']}"


def _delete_file(state: SandboxState, args: Mapping[str, str]) -> str:
    if args["path"] not in state.files:
        raise ToolExecutionError(f"file not found: {args['path']}")
    del state.files[args["path"]]
    return f"deleted {args['path']}"


DEFAULT_HANDLERS: Mapping[str, Handler] = {
    "read_file": _read_file,
    "get_balance": _get_balance,
    "send_money": _send_money,
    "send_email": _send_email,
    "write_file": _write_file,
    "delete_file": _delete_file,
}


class MockToolBackend:
    """The only tool backend the executor accepts (SEC-015)."""

    def __init__(self, extra_handlers: Mapping[str, Handler] | None = None) -> None:
        self._handlers: dict[str, Handler] = {**DEFAULT_HANDLERS, **(extra_handlers or {})}

    def has(self, tool: str) -> bool:
        return tool in self._handlers

    def run(self, tool: str, state: SandboxState, args: Mapping[str, str]) -> str:
        try:
            handler = self._handlers[tool]
        except KeyError as exc:
            raise ToolExecutionError(f"no mock implementation for {tool}") from exc
        return handler(state, args)
