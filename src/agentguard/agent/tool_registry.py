"""Tool registry: schemas, protected flags, argument validation and normalization."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterable, Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentguard.agent.model_adapter import ToolSchema
from agentguard.errors import ConfigError, InvalidCallError, NormalizationError
from agentguard.normalize import (
    normalize_account,
    normalize_amount,
    normalize_bool,
    normalize_email,
    normalize_iban,
    normalize_integer,
    normalize_path,
    normalize_relpath,
    normalize_text,
)
from agentguard.policy.schemas import NormalizedCall, ToolCall

_TOOL_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class ParamType(StrEnum):
    EMAIL = "email"
    IBAN = "iban"
    PATH = "path"
    AMOUNT = "amount"
    TEXT = "text"
    INTEGER = "integer"
    BOOL = "bool"
    RELPATH = "relpath"  # relative file name (benchmark file systems)
    ACCOUNT = "account"  # IBAN or payee name


NORMALIZERS: Mapping[ParamType, Callable[[Any], str]] = {
    ParamType.EMAIL: normalize_email,
    ParamType.IBAN: normalize_iban,
    ParamType.PATH: normalize_path,
    ParamType.AMOUNT: normalize_amount,
    ParamType.TEXT: normalize_text,
    ParamType.INTEGER: normalize_integer,
    ParamType.BOOL: normalize_bool,
    ParamType.RELPATH: normalize_relpath,
    ParamType.ACCOUNT: normalize_account,
}


class ParamSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: ParamType
    required: bool = True
    # Security-relevant arguments (recipient, destination, path, amount) must be constrained by
    # an allow-capability, otherwise the capability does not match (SEC-005).
    security_relevant: bool = False


class ToolSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str = ""
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    protected: bool = False


class ToolRegistry:
    """Immutable set of tool specifications."""

    def __init__(self, specs: Iterable[ToolSpec]) -> None:
        by_name: dict[str, ToolSpec] = {}
        for spec in specs:
            if not _TOOL_NAME_RE.fullmatch(spec.name):
                raise ConfigError(f"illegal tool name: {spec.name!r}")
            if spec.name in by_name:
                raise ConfigError(f"duplicate tool: {spec.name}")
            by_name[spec.name] = spec
        self._specs: dict[str, ToolSpec] = by_name

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(self._specs.values())

    def tool_schemas(self) -> tuple[ToolSchema, ...]:
        """Function-calling schemas exposed to the model (identical in every configuration)."""
        hints = {
            ParamType.EMAIL: "e-mail address",
            ParamType.IBAN: "IBAN account number",
            ParamType.PATH: "absolute file path",
            ParamType.AMOUNT: "amount with at most two decimals",
            ParamType.TEXT: "text",
            ParamType.INTEGER: "integer",
            ParamType.BOOL: "true or false",
            ParamType.RELPATH: "file name",
            ParamType.ACCOUNT: "IBAN or payee name",
        }
        out = []
        for spec in self._specs.values():
            props = {
                n: {
                    "type": {
                        ParamType.AMOUNT: "number",
                        ParamType.INTEGER: "integer",
                        ParamType.BOOL: "boolean",
                    }.get(p.type, "string"),
                    "description": hints[p.type],
                }
                for n, p in spec.params.items()
            }
            out.append(
                ToolSchema(
                    name=spec.name,
                    description=spec.description,
                    parameters={
                        "type": "object",
                        "properties": props,
                        "required": [n for n, p in spec.params.items() if p.required],
                    },
                )
            )
        return tuple(out)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def validate(self, raw: ToolCall, task_id: str) -> NormalizedCall:
        """Validate and normalize a proposed call; raises InvalidCallError on any defect."""
        spec = self._specs.get(raw.tool)
        if spec is None:
            raise InvalidCallError(f"unknown tool: {raw.tool[:64]!r}")
        unknown = sorted(set(raw.args) - set(spec.params))
        if unknown:
            raise InvalidCallError(f"unexpected arguments for {spec.name}: {unknown}")
        normalized: dict[str, str] = {}
        for pname, pspec in spec.params.items():
            if pname not in raw.args:
                if pspec.required:
                    raise InvalidCallError(f"missing required argument {pname!r} for {spec.name}")
                continue
            try:
                normalized[pname] = NORMALIZERS[pspec.type](raw.args[pname])
            except NormalizationError as exc:
                raise InvalidCallError(
                    f"invalid argument {pname!r} for {spec.name}: {exc}"
                ) from exc
        return NormalizedCall(
            task_id=task_id,
            call_id=uuid.uuid4().hex,
            tool=spec.name,
            args=normalized,
            raw_args=dict(raw.args),
            protected=spec.protected,
        )

    def normalize_constraint_value(self, tool: str, param: str, value: str) -> str:
        """Normalize a policy constant with the same normalizer the call argument gets."""
        spec = self._specs.get(tool)
        if spec is None or param not in spec.params:
            raise ConfigError(f"policy refers to unknown {tool}.{param}")
        return NORMALIZERS[spec.params[param].type](value)


def default_registry() -> ToolRegistry:
    """Simulated banking/email/file tools used by the M3 vertical slice."""
    return ToolRegistry(
        [
            ToolSpec(
                name="read_file",
                description="Read a file from the sandbox file system.",
                params={"path": ParamSpec(type=ParamType.PATH, security_relevant=True)},
            ),
            ToolSpec(name="get_balance", description="Return the account balance."),
            ToolSpec(
                name="send_money",
                description="Send money to an IBAN (simulated).",
                params={
                    "recipient_iban": ParamSpec(type=ParamType.IBAN, security_relevant=True),
                    "amount": ParamSpec(type=ParamType.AMOUNT, security_relevant=True),
                    "subject": ParamSpec(type=ParamType.TEXT),
                },
                protected=True,
            ),
            ToolSpec(
                name="send_email",
                description="Send an e-mail (simulated outbox only).",
                params={
                    "to": ParamSpec(type=ParamType.EMAIL, security_relevant=True),
                    "subject": ParamSpec(type=ParamType.TEXT),
                    "body": ParamSpec(type=ParamType.TEXT),
                },
                protected=True,
            ),
            ToolSpec(
                name="write_file",
                description="Create or overwrite a file in the sandbox.",
                params={
                    "path": ParamSpec(type=ParamType.PATH, security_relevant=True),
                    "content": ParamSpec(type=ParamType.TEXT),
                },
                protected=True,
            ),
            ToolSpec(
                name="delete_file",
                description="Delete a file in the sandbox.",
                params={"path": ParamSpec(type=ParamType.PATH, security_relevant=True)},
                protected=True,
            ),
        ]
    )
