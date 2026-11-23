"""Model adapter interface and the Ollama implementation.

Design rules:
* Every failure mode is a distinct exception (never an empty "successful" response), so the
  orchestrator can record an error status instead of a silent success (REQ-ORC-4).
* Only loopback hosts are accepted. Remote or paid endpoints need explicit human approval
  (REQ-GOV-1) and a separate, reviewed adapter.
* The Ollama adapter uses the native ``/api/chat`` endpoint so that ``num_ctx``, ``seed`` and
  ``temperature`` are set per request and exact token counts are returned.
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agentguard.errors import AgentGuardError, ConfigError

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
CONTEXT_FILL_LIMIT = 0.95  # fraction of num_ctx above which we assume silent truncation


class ModelError(AgentGuardError):
    """Base class for model-side failures."""


class ModelTimeout(ModelError):
    pass


class ModelUnavailable(ModelError):
    """The model server cannot be reached or refused the request."""


class ModelProtocolError(ModelError):
    """The response did not have the expected structure."""


class ContextOverflow(ModelError):
    """The prompt (plus output) filled the context window; truncation cannot be excluded."""


class ToolSchema(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    parameters: dict[str, Any]


class Usage(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0


class ModelToolCall(BaseModel):
    """A tool call as emitted by the model. ``arguments`` is whatever the model produced."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    arguments: Any


class ChatMessage(BaseModel):
    model_config = ConfigDict(frozen=True)

    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_calls: tuple[ModelToolCall, ...] = ()
    tool_name: str | None = None  # for role == "tool"


class ModelResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    content: str = ""
    tool_calls: tuple[ModelToolCall, ...] = ()
    usage: Usage = Field(default_factory=Usage)
    latency_s: float = 0.0
    finish_reason: str | None = None


class ModelAdapter(Protocol):
    @property
    def model_id(self) -> str: ...

    @property
    def params(self) -> dict[str, Any]:
        """Generation parameters to be stored with every experiment record."""
        ...

    def digest(self) -> str | None:
        """Content digest of the model weights if the backend can tell, else None."""
        ...

    def chat(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSchema], *, timeout_s: float
    ) -> ModelResponse: ...


# ---------------------------------------------------------------------------------------
Transport = Callable[[str, dict[str, Any], float], dict[str, Any]]


def _http_post_json(url: str, payload: dict[str, Any], timeout_s: float) -> dict[str, Any]:
    req = urllib.request.Request(  # noqa: S310 - scheme and host are validated in OllamaConfig
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            body = resp.read()
    except TimeoutError as exc:
        raise ModelTimeout(f"no response within {timeout_s}s") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise ModelTimeout(f"no response within {timeout_s}s") from exc
        raise ModelUnavailable(f"model server unreachable: {exc.reason}") from exc
    except OSError as exc:
        raise ModelUnavailable(f"model server error: {exc}") from exc
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ModelProtocolError("response is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ModelProtocolError("response is not a JSON object")
    return data


def _http_get_json(url: str, timeout_s: float) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET")  # noqa: S310 - loopback only, see OllamaConfig
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            data = json.loads(resp.read())
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelUnavailable(f"cannot query model server: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelProtocolError("response is not a JSON object")
    return data


class OllamaConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str
    host: str = "http://localhost:11434"
    num_ctx: int = Field(default=8192, ge=512)
    temperature: float = Field(default=0.0, ge=0.0)
    seed: int = 0
    max_output_tokens: int = Field(default=1024, ge=16)
    think: bool | None = None  # None = model default; False/True forces reasoning off/on

    def validated_host(self) -> str:
        parsed = urllib.parse.urlparse(self.host)
        if parsed.scheme != "http" or (parsed.hostname or "") not in LOOPBACK_HOSTS:
            raise ConfigError(
                "only local (loopback) model servers are allowed without explicit approval"
            )
        return self.host.rstrip("/")


def _to_ollama_message(m: ChatMessage) -> dict[str, Any]:
    out: dict[str, Any] = {"role": m.role, "content": m.content}
    if m.tool_calls:
        out["tool_calls"] = [
            {
                "function": {
                    "name": c.name,
                    "arguments": c.arguments if isinstance(c.arguments, dict) else {},
                }
            }
            for c in m.tool_calls
        ]
    if m.role == "tool" and m.tool_name:
        out["tool_name"] = m.tool_name
    return out


class OllamaAdapter:
    def __init__(
        self,
        config: OllamaConfig,
        transport: Transport | None = None,
        get_transport: Callable[[str, float], dict[str, Any]] | None = None,
    ) -> None:
        self._cfg = config
        self._base = config.validated_host()
        self._transport = transport or _http_post_json
        self._get = get_transport or _http_get_json
        self._counter = 0
        self._digest: str | None = None

    def digest(self) -> str | None:
        """Digest of the exact model weights, from /api/tags (cached). None if unavailable."""
        if self._digest is None:
            try:
                tags = self._get(f"{self._base}/api/tags", 10.0)
            except ModelError:
                return None
            for m in tags.get("models", []):
                if isinstance(m, dict) and m.get("name") in (
                    self._cfg.model,
                    f"{self._cfg.model}:latest",
                ):
                    d = m.get("digest")
                    self._digest = d if isinstance(d, str) else None
        return self._digest

    @property
    def model_id(self) -> str:
        return self._cfg.model

    @property
    def params(self) -> dict[str, Any]:
        return {
            "backend": "ollama",
            "num_ctx": self._cfg.num_ctx,
            "temperature": self._cfg.temperature,
            "seed": self._cfg.seed,
            "max_output_tokens": self._cfg.max_output_tokens,
            "think": self._cfg.think,
        }

    def chat(
        self, messages: Sequence[ChatMessage], tools: Sequence[ToolSchema], *, timeout_s: float
    ) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self._cfg.model,
            "stream": False,
            "messages": [_to_ollama_message(m) for m in messages],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ],
            "options": {
                "num_ctx": self._cfg.num_ctx,
                "temperature": self._cfg.temperature,
                "seed": self._cfg.seed,
                "num_predict": self._cfg.max_output_tokens,
            },
        }
        if self._cfg.think is not None:
            payload["think"] = self._cfg.think

        started = time.monotonic()
        data = self._transport(f"{self._base}/api/chat", payload, timeout_s)
        latency = time.monotonic() - started
        return self._parse(data, latency)

    def _parse(self, data: dict[str, Any], latency: float) -> ModelResponse:
        if "error" in data:
            raise ModelUnavailable(f"model server reported an error: {str(data['error'])[:200]}")
        message = data.get("message")
        if not isinstance(message, dict):
            raise ModelProtocolError("response has no 'message' object")
        content = message.get("content", "")
        if not isinstance(content, str):
            raise ModelProtocolError("message content is not a string")
        raw_calls = message.get("tool_calls") or []
        if not isinstance(raw_calls, list):
            raise ModelProtocolError("tool_calls is not a list")
        calls: list[ModelToolCall] = []
        for raw in raw_calls:
            fn = raw.get("function") if isinstance(raw, dict) else None
            if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
                raise ModelProtocolError("tool call without a function name")
            args = fn.get("arguments", {})
            if isinstance(args, str):  # some models return a JSON string; keep raw if unparsable
                with contextlib.suppress(json.JSONDecodeError):
                    args = json.loads(args)
            self._counter += 1
            calls.append(ModelToolCall(id=f"call_{self._counter}", name=fn["name"], arguments=args))

        n_in, n_out = data.get("prompt_eval_count"), data.get("eval_count")
        if not isinstance(n_in, int) or not isinstance(n_out, int):
            raise ModelProtocolError("token counts missing from response")
        if n_in + n_out >= int(self._cfg.num_ctx * CONTEXT_FILL_LIMIT):
            raise ContextOverflow(
                f"{n_in}+{n_out} tokens fill >= {CONTEXT_FILL_LIMIT:.0%} "
                f"of num_ctx={self._cfg.num_ctx}"
            )
        return ModelResponse(
            content=content,
            tool_calls=tuple(calls),
            usage=Usage(input_tokens=n_in, output_tokens=n_out),
            latency_s=latency,
            finish_reason=data.get("done_reason"),
        )
