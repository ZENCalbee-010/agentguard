"""Value normalizers used before any security decision (SEC-004, SEC-011).

Pure functions with no dependency on policy, defense or agent code, so the evaluation
oracle can use them without breaking its independence from the defense (REQ-ORC-2).
Every normalizer raises :class:`NormalizationError` on anything it cannot make canonical.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import unquote

from agentguard.errors import NormalizationError

MAX_TEXT_LENGTH = 10_000
_MAX_PERCENT_DECODE_ROUNDS = 3

_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)+")
_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TWO_PLACES = Decimal("0.01")
_MAX_AMOUNT = Decimal("1000000000")  # far above any sandbox balance; bounds all arithmetic


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise NormalizationError(f"{what} must be a string, got {type(value).__name__}")
    return value


def normalize_email(value: Any) -> str:
    """Lower-case and strip; ASCII addresses only (rejects look-alike Unicode)."""
    raw = _require_str(value, "email")
    if not raw.isascii():  # lower() can also change length/shape for some Unicode letters
        raise NormalizationError("email must be ASCII")
    s = raw.strip().lower()
    if _CONTROL_RE.search(s) or not _EMAIL_RE.fullmatch(s):
        raise NormalizationError("malformed email address")
    return s


def normalize_iban(value: Any) -> str:
    """Remove spaces/hyphens, upper-case, structural check (no checksum: synthetic data)."""
    raw = _require_str(value, "iban")
    if not raw.isascii():  # upper() can expand characters (e.g. sharp s -> SS): reject, never guess
        raise NormalizationError("IBAN must be ASCII")
    s = re.sub(r"[ \-]", "", raw).upper()
    if not _IBAN_RE.fullmatch(s):
        raise NormalizationError("malformed IBAN")
    return s


def normalize_path(value: Any) -> str:
    """Resolve to an absolute virtual POSIX path.

    Percent-decoding is applied repeatedly (bounded), backslashes become slashes,
    relative paths are anchored at ``/``, ``.``/``..``/empty segments are resolved, and
    any attempt to climb above the root is an error rather than being silently clamped.
    """
    s = _require_str(value, "path")
    for _ in range(_MAX_PERCENT_DECODE_ROUNDS):
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    else:
        if unquote(s) != s:
            raise NormalizationError("path has excessive percent-encoding")
    if _CONTROL_RE.search(s):
        raise NormalizationError("path contains control characters")
    parts: list[str] = []
    for seg in s.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                raise NormalizationError("path escapes the root")
            parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts)


def path_is_within(path: str, prefix: str) -> bool:
    """True if normalized ``path`` equals or is below normalized ``prefix`` (segment-aware)."""
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def normalize_amount(value: Any) -> str:
    """Positive, finite, at most two decimal places; returned as a canonical string."""
    if isinstance(value, bool) or not isinstance(value, int | float | str | Decimal):
        raise NormalizationError("amount must be a number")
    try:
        d = Decimal(str(value).strip())
    except InvalidOperation as exc:
        raise NormalizationError("amount is not a number") from exc
    if not d.is_finite() or d <= 0 or d > _MAX_AMOUNT:
        raise NormalizationError("amount must be positive, finite and within range")
    try:
        q = d.quantize(_TWO_PLACES)
    except InvalidOperation as exc:  # defensive: never let a Decimal error escape as a crash
        raise NormalizationError("amount cannot be represented with two decimals") from exc
    if d != q:
        raise NormalizationError("amount has more than two decimal places")
    return str(q)


def normalize_text(value: Any) -> str:
    s = _require_str(value, "text")
    if len(s) > MAX_TEXT_LENGTH or "\x00" in s:
        raise NormalizationError("text too long or contains NUL")
    return s


_MAX_ACCOUNT_NAME = 64
_MAX_INTEGER = 10**9


def normalize_integer(value: Any) -> str:
    """Non-negative integer (bool and non-integral floats are rejected)."""
    if isinstance(value, bool):
        raise NormalizationError("integer must not be a boolean")
    if isinstance(value, float):
        if not value.is_integer():
            raise NormalizationError("integer expected")
        value = int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s.isascii() or not s.isdigit():
            raise NormalizationError("integer expected")
        value = int(s)
    if not isinstance(value, int) or value < 0 or value > _MAX_INTEGER:
        raise NormalizationError("integer out of range")
    return str(value)


def normalize_bool(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower()
    raise NormalizationError("boolean expected")


def normalize_relpath(value: Any) -> str:
    """Relative file name as used by benchmark file systems: no leading slash, no traversal."""
    s = _require_str(value, "file name")
    for _ in range(_MAX_PERCENT_DECODE_ROUNDS):
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    else:
        if unquote(s) != s:
            raise NormalizationError("file name has excessive percent-encoding")
    if _CONTROL_RE.search(s):
        raise NormalizationError("file name contains control characters")
    s = s.strip().replace("\\", "/")
    if s.startswith("/"):
        raise NormalizationError("file name must be relative")
    parts = [seg for seg in s.split("/") if seg not in ("", ".")]
    if not parts or ".." in parts:
        raise NormalizationError("file name is empty or traverses upwards")
    return "/".join(parts)


def normalize_account(value: Any) -> str:
    """A payment recipient: an IBAN (canonicalized) or a short ASCII payee name (case-folded)."""
    raw = _require_str(value, "account")
    if not raw.isascii() or _CONTROL_RE.search(raw):  # reject before whitespace is collapsed
        raise NormalizationError("account must be printable ASCII")
    squashed = re.sub(r"[ \-]", "", raw).upper()
    if _IBAN_RE.fullmatch(squashed):
        return squashed
    name = " ".join(raw.split()).casefold()
    if not name or len(name) > _MAX_ACCOUNT_NAME or _CONTROL_RE.search(name):
        raise NormalizationError("malformed account name")
    return name
