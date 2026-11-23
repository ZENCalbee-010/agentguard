from __future__ import annotations

import pytest

from agentguard.errors import NormalizationError
from agentguard.normalize import (
    normalize_amount,
    normalize_email,
    normalize_iban,
    normalize_path,
    normalize_text,
    path_is_within,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/docs/a.txt", "/docs/a.txt"),
        ("docs/a.txt", "/docs/a.txt"),
        ("/docs/./a.txt", "/docs/a.txt"),
        ("/docs//a.txt", "/docs/a.txt"),
        ("/docs/sub/../a.txt", "/docs/a.txt"),
        ("\\docs\\a.txt", "/docs/a.txt"),
        ("/docs/%61.txt", "/docs/a.txt"),
        ("/", "/"),
        ("", "/"),
    ],
)
def test_path_canonical_forms(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "/../etc/passwd",
        "/docs/../../etc",
        "..\\secrets",
        "/docs/%2e%2e/%2e%2e/etc",
        "/docs/%252e%252e/%252e%252e/etc",  # double encoded
        "/docs/a\x00.txt",
        "/docs/%25252561.txt",  # needs 4 decode rounds; we allow 3
        None,
        123,
    ],
)
def test_path_rejects_hostile_input(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_path(raw)


def test_path_within_is_segment_aware() -> None:
    assert path_is_within("/bills/dec.txt", "/bills")
    assert path_is_within("/bills", "/bills")
    assert not path_is_within("/bills-evil/x", "/bills")
    assert not path_is_within("/billsx", "/bills")
    assert path_is_within("/anything", "/")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Alice@Example.COM", "alice@example.com"), ("  bob@x.org \n", "bob@x.org")],
)
def test_email_ok(raw: str, expected: str) -> None:
    assert normalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "no-at-sign",
        "a@b",
        "a@@b.com",
        chr(0xFF41) + "lice@example.com",
        "a b@x.com",
        "a@x.com\nbcc:e@e.com",
        5,
    ],
)
def test_email_rejects(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_email(raw)


def test_iban_canonicalization() -> None:
    assert normalize_iban("us13 3000 0001 2121 2121 212") == "US133000000121212121212"
    assert normalize_iban("UK12-3456-7890-1234-5678-90") == "UK12345678901234567890"


@pytest.mark.parametrize("raw", ["", "12345", "US13", "US13$$$$$$$$$$$$", None])
def test_iban_rejects(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_iban(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(98.7, "98.70"), (100, "100.00"), ("0.01", "0.01"), (" 5.5 ", "5.50")],
)
def test_amount_ok(raw: object, expected: str) -> None:
    assert normalize_amount(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [0, -1, "abc", "NaN", "Infinity", True, None, 0.001, "1e400", "1e9999999", "1000000001", [1]],
)
def test_amount_rejects(raw: object) -> None:
    with pytest.raises(NormalizationError):
        normalize_amount(raw)


def test_text_limits() -> None:
    assert normalize_text("ok") == "ok"
    with pytest.raises(NormalizationError):
        normalize_text("x" * 10_001)
    with pytest.raises(NormalizationError):
        normalize_text("a\x00b")
    with pytest.raises(NormalizationError):
        normalize_text(None)
