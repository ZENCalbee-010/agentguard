from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from agentguard.agent.model_adapter import (
    ChatMessage,
    ContextOverflow,
    ModelProtocolError,
    ModelTimeout,
    ModelToolCall,
    ModelUnavailable,
    OllamaAdapter,
    OllamaConfig,
    ToolSchema,
    _http_post_json,
)
from agentguard.errors import ConfigError

TOOLS = [
    ToolSchema(name="get_balance", description="d", parameters={"type": "object", "properties": {}})
]
MSGS = [ChatMessage(role="user", content="hi")]


def _ok(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "message": {"role": "assistant", "content": "done"},
        "prompt_eval_count": 100,
        "eval_count": 20,
        "done_reason": "stop",
    }
    base.update(over)
    return base


def _adapter(response: Any, **cfg: Any) -> tuple[OllamaAdapter, list[dict[str, Any]]]:
    sent: list[dict[str, Any]] = []

    def transport(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        sent.append({"url": url, "payload": payload, "timeout": timeout})
        if isinstance(response, Exception):
            raise response
        return response  # type: ignore[no-any-return]

    return OllamaAdapter(OllamaConfig(model="m", **cfg), transport), sent


def test_request_pins_generation_parameters_per_request() -> None:
    ad, sent = _adapter(_ok(), num_ctx=4096, seed=7, temperature=0.0)
    ad.chat(MSGS, TOOLS, timeout_s=5)
    p = sent[0]["payload"]
    assert sent[0]["url"] == "http://localhost:11434/api/chat" and sent[0]["timeout"] == 5
    assert p["stream"] is False and p["options"]["num_ctx"] == 4096 and p["options"]["seed"] == 7
    assert p["tools"][0]["function"]["name"] == "get_balance" and "think" not in p
    assert ad.params["num_ctx"] == 4096 and ad.model_id == "m"


def test_think_flag_is_sent_only_when_set() -> None:
    ad, sent = _adapter(_ok(), think=False)
    ad.chat(MSGS, TOOLS, timeout_s=5)
    assert sent[0]["payload"]["think"] is False


def test_parses_text_usage_and_finish_reason() -> None:
    ad, _ = _adapter(_ok())
    r = ad.chat(MSGS, TOOLS, timeout_s=5)
    assert (r.content, r.usage.input_tokens, r.usage.output_tokens, r.finish_reason) == (
        "done",
        100,
        20,
        "stop",
    )
    assert r.tool_calls == () and r.latency_s >= 0


def test_parses_tool_calls_and_keeps_unparsable_arguments_raw() -> None:
    calls = [
        {"function": {"name": "a", "arguments": {"x": 1}}},
        {"function": {"name": "b", "arguments": '{"y": 2}'}},
        {"function": {"name": "c", "arguments": "not json"}},
    ]
    ad, _ = _adapter(_ok(message={"role": "assistant", "content": "", "tool_calls": calls}))
    out = ad.chat(MSGS, TOOLS, timeout_s=5).tool_calls
    assert [c.arguments for c in out] == [{"x": 1}, {"y": 2}, "not json"]
    assert len({c.id for c in out}) == 3


@pytest.mark.parametrize(
    ("response", "exc"),
    [
        ({"error": "model not found"}, ModelUnavailable),
        ({}, ModelProtocolError),
        ({"message": "text"}, ModelProtocolError),
        (_ok(message={"content": 5}), ModelProtocolError),
        (_ok(message={"content": "", "tool_calls": "x"}), ModelProtocolError),
        (
            _ok(message={"content": "", "tool_calls": [{"function": {"arguments": {}}}]}),
            ModelProtocolError,
        ),
        (_ok(message={"content": "", "tool_calls": ["junk"]}), ModelProtocolError),
        ({"message": {"content": "x"}}, ModelProtocolError),  # token counts missing
        (_ok(prompt_eval_count="many"), ModelProtocolError),
        (_ok(prompt_eval_count=7900, eval_count=100), ContextOverflow),  # 8000/8192 >= 95%
    ],
)
def test_bad_responses_raise_specific_errors(response: Any, exc: type[Exception]) -> None:
    ad, _ = _adapter(response)
    with pytest.raises(exc):
        ad.chat(MSGS, TOOLS, timeout_s=5)


def test_context_just_below_limit_is_accepted() -> None:
    ad, _ = _adapter(_ok(prompt_eval_count=7000, eval_count=500))
    assert ad.chat(MSGS, TOOLS, timeout_s=5).usage.input_tokens == 7000


def test_transport_errors_propagate() -> None:
    ad, _ = _adapter(ModelTimeout("slow"))
    with pytest.raises(ModelTimeout):
        ad.chat(MSGS, TOOLS, timeout_s=1)


@pytest.mark.parametrize(
    "host",
    [
        "http://example.com:11434",
        "https://localhost:11434",
        "http://192.168.1.5:11434",
        "ftp://localhost",
    ],
)
def test_non_loopback_or_non_http_hosts_are_refused(host: str) -> None:
    with pytest.raises(ConfigError):
        OllamaAdapter(OllamaConfig(model="m", host=host))


@pytest.mark.parametrize("host", ["http://localhost:11434", "http://127.0.0.1:9999/"])
def test_loopback_hosts_are_accepted(host: str) -> None:
    OllamaAdapter(OllamaConfig(model="m", host=host))


def test_history_serialization_includes_tool_calls_and_tool_names() -> None:
    ad, sent = _adapter(_ok())
    history = [
        ChatMessage(role="user", content="q"),
        ChatMessage(
            role="assistant", tool_calls=(ModelToolCall(id="1", name="get_balance", arguments={}),)
        ),
        ChatMessage(role="tool", content="1000.00", tool_name="get_balance"),
    ]
    ad.chat(history, TOOLS, timeout_s=5)
    msgs = sent[0]["payload"]["messages"]
    assert msgs[1]["tool_calls"][0]["function"]["name"] == "get_balance"
    assert msgs[2]["tool_name"] == "get_balance"


# ---- real sockets on loopback (no model server involved) --------------------------------
@pytest.fixture
def silent_server() -> Iterator[int]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    conns: list[socket.socket] = []

    def accept() -> None:
        try:
            c, _ = srv.accept()
            conns.append(c)  # accept, read nothing, never answer
        except OSError:
            pass

    threading.Thread(target=accept, daemon=True).start()
    yield srv.getsockname()[1]
    for c in conns:
        c.close()
    srv.close()


def test_unresponsive_server_raises_model_timeout(silent_server: int) -> None:
    with pytest.raises(ModelTimeout):
        _http_post_json(f"http://127.0.0.1:{silent_server}/api/chat", {}, 0.4)


def test_closed_port_raises_model_unavailable() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    with pytest.raises(ModelUnavailable):
        _http_post_json(
            f"http://127.0.0.1:{port}/api/chat", {}, 6.0
        )  # Windows needs ~2s to report refusal


def test_digest_comes_from_tags_is_cached_and_failure_is_none() -> None:
    calls: list[str] = []

    def get(url: str, timeout: float) -> dict[str, Any]:
        calls.append(url)
        return {
            "models": [{"name": "other", "digest": "x"}, {"name": "m:latest", "digest": "abc123"}]
        }

    ad = OllamaAdapter(OllamaConfig(model="m"), get_transport=get)
    assert ad.digest() == "abc123" and ad.digest() == "abc123"
    assert calls == ["http://localhost:11434/api/tags"]  # cached after the first lookup

    def broken(url: str, timeout: float) -> dict[str, Any]:
        raise ModelUnavailable("down")

    assert OllamaAdapter(OllamaConfig(model="m"), get_transport=broken).digest() is None
    unknown = OllamaAdapter(OllamaConfig(model="zzz"), get_transport=get)
    assert unknown.digest() is None
