"""Scoped capability store and the trusted channel that alone may change permissions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from decimal import Decimal, InvalidOperation

from agentguard.agent.tool_registry import ParamType, ToolRegistry
from agentguard.errors import ConfigError, NormalizationError, PermissionChangeRejected, PolicyError
from agentguard.normalize import normalize_path
from agentguard.policy.schemas import Capability, Constraint, Policy


class TrustedChannel:
    """Root of trust for permission changes (SEC-008).

    Whoever holds the instance can mint tokens. The agent loop never receives it; the
    gateway keeps only its ``verify`` method.
    """

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)

    def _tag(self, task_id: str, cap_id: str) -> str:
        msg = f"grant|{task_id}|{cap_id}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def mint(self, task_id: str, capability: Capability) -> str:
        return self._tag(task_id, capability.cap_id)

    def verify(self, task_id: str, capability: Capability, token: str) -> bool:
        return hmac.compare_digest(self._tag(task_id, capability.cap_id), token)


def normalize_capability(cap: Capability, registry: ToolRegistry) -> Capability:
    """Normalize every constant in a capability with the same normalizers calls get.

    Fails closed: unknown tools/params, or predicates that do not fit the parameter type,
    raise PolicyError so a malformed policy can never be loaded.
    """
    spec = registry.spec(cap.tool)
    if spec is None:
        raise PolicyError(f"capability for unknown tool {cap.tool!r}")
    constraints: dict[str, Constraint] = {}
    for pname, c in cap.constraints.items():
        pspec = spec.params.get(pname)
        if pspec is None:
            raise PolicyError(f"{cap.tool} has no parameter {pname!r}")
        try:
            if c.equals is not None:
                constraints[pname] = Constraint(
                    equals=registry.normalize_constraint_value(cap.tool, pname, c.equals)
                )
            elif c.one_of is not None:
                constraints[pname] = Constraint(
                    one_of=tuple(
                        registry.normalize_constraint_value(cap.tool, pname, v) for v in c.one_of
                    )
                )
            elif c.path_prefix is not None:
                if pspec.type is not ParamType.PATH:
                    raise PolicyError(f"path_prefix on non-path parameter {cap.tool}.{pname}")
                constraints[pname] = Constraint(path_prefix=normalize_path(c.path_prefix))
            elif c.any_value:
                constraints[pname] = c
            elif c.absent:
                if pspec.required:
                    raise PolicyError(f"absent on required parameter {cap.tool}.{pname}")
                constraints[pname] = c
            else:
                if pspec.type is not ParamType.AMOUNT:
                    raise PolicyError(f"max_value on non-amount parameter {cap.tool}.{pname}")
                try:
                    ok = c.max_value is not None and Decimal(c.max_value).is_finite()
                except InvalidOperation:
                    ok = False
                if not ok:
                    raise PolicyError("max_value must be a finite number")
                constraints[pname] = c
        except (NormalizationError, ConfigError) as exc:
            raise PolicyError(f"bad constraint on {cap.tool}.{pname}: {exc}") from exc
    return Capability(
        tool=cap.tool, effect=cap.effect, constraints=constraints, max_calls=cap.max_calls
    )


class CapabilityStore:
    """Per-task, read-only view of the granted capabilities."""

    def __init__(
        self,
        task_id: str,
        policy: Policy,
        registry: ToolRegistry,
        verify_token: Callable[[str, Capability, str], bool],
    ) -> None:
        self._task_id = task_id
        self._registry = registry
        self._verify = verify_token
        self._caps: tuple[Capability, ...] = tuple(
            normalize_capability(c, registry) for c in policy.capabilities
        )
        self._version = policy.version

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return self._caps

    @property
    def policy(self) -> Policy:
        return Policy(version=self._version, capabilities=self._caps)

    @property
    def policy_hash(self) -> str:
        return self.policy.policy_hash

    def grant(self, capability: Capability, token: str) -> Capability:
        """Add a capability. Only a token from the trusted channel is accepted."""
        if not isinstance(token, str) or not self._verify(self._task_id, capability, token):
            raise PermissionChangeRejected(
                "permission change did not come through the trusted channel"
            )
        normalized = normalize_capability(capability, self._registry)
        self._caps = (*self._caps, normalized)
        return normalized
