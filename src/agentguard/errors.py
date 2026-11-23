"""Exception types shared across AgentGuard components."""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base class for all AgentGuard errors."""


class ConfigError(AgentGuardError):
    """Invalid or unsafe configuration; the system refuses to start (fail closed)."""


class NormalizationError(AgentGuardError, ValueError):
    """A value could not be normalized to a safe canonical form."""


class InvalidCallError(AgentGuardError):
    """A proposed tool call is malformed, unknown, or fails schema validation."""


class PolicyError(AgentGuardError):
    """A policy is malformed or cannot be evaluated."""


class UnauthorizedExecution(AgentGuardError):
    """Execution was attempted without a valid, matching ALLOW decision."""


class PermissionChangeRejected(AgentGuardError):
    """A permission change did not arrive through the trusted channel."""


class ToolExecutionError(AgentGuardError):
    """A mock tool failed while executing; sandbox state is rolled back."""
