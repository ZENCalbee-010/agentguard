"""Context analyzer v0: transparent, deterministic heuristics (docs/spec/architecture.md section 3).

Signals (all computed from the trusted prompt, the validated call and untrusted items):

* S1 value provenance - a security-relevant argument (e-mail, IBAN, path) of the call appears in
  untrusted text but not in the trusted prompt.
* S2 instruction-like content - untrusted text matches override/imperative patterns.
* S3 tool-intent alignment - a protected tool whose purpose is not mentioned by the prompt.
* S4 temporal coupling - S2 fired in the most recent untrusted item.

``score = min(1, w1*S1 + w2*S2 + w3*S3 + w4*S4)``; DENY iff ``score >= threshold``.

Pre-declared a priori (not tuned on any evaluation data): weights and threshold below. Any later
tuning must use the development split only and produce a new version (REQ-CA-4). The patterns
are generic and contain no benchmark- or attacker-specific constants (checked by a test).
The analyzer can only restrict; it never sees or changes policy (SEC-006).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from agentguard.agent.tool_registry import ParamType, ToolRegistry
from agentguard.policy.schemas import (
    AnalyzerVerdict,
    ContextItem,
    NormalizedCall,
    Verdict,
    canonical_json,
    sha256_hex,
)

MAX_ITEM_CHARS = 20_000  # bound work per item (no catastrophic regex input)

DEFAULT_PATTERNS = (
    r"ignore (all|any|previous|prior|the above|your)",
    r"disregard",
    r"new instructions?",
    r"<information>",
    r"important (message|instruction)",
    r"before you (can )?(solve|continue|proceed|do|finish)",
    r"you (must|should|have to) (first |now |also )?(send|transfer|pay|email|forward|delete|write)",
    r"(system|admin(istrator)?) (message|override|notice|instruction)",
    r"do not (tell|inform|mention|notify)",
    r"instead (of|,)? ?(send|transfer|pay|email|forward|delete)",
    r"(also|then|first),? (please )?(send|transfer|pay|email|forward|delete)",
)

DEFAULT_TOOL_VERBS: dict[str, tuple[str, ...]] = {
    "send_money": ("pay", "send", "transfer", "money", "payment", "bill"),
    "send_email": ("email", "e-mail", "mail", "send", "forward", "message"),
    "write_file": ("write", "create", "save", "copy", "note", "file"),
    "delete_file": ("delete", "remove", "erase", "clean"),
}


class AnalyzerConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = "v0.1"
    w_provenance: float = Field(default=0.4, ge=0)
    w_instruction: float = Field(default=0.4, ge=0)
    w_alignment: float = Field(default=0.2, ge=0)
    w_temporal: float = Field(default=0.2, ge=0)
    threshold: float = Field(default=0.6, gt=0, le=1)
    patterns: tuple[str, ...] = DEFAULT_PATTERNS
    tool_verbs: dict[str, tuple[str, ...]] = Field(default_factory=lambda: dict(DEFAULT_TOOL_VERBS))

    @property
    def config_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))[:12]


def _squash(text: str) -> str:
    """Comparison form: lower-case, no spaces/hyphens (so spaced IBANs and e-mails still match)."""
    return re.sub(r"[\s\-]", "", text.lower())


class ContextAnalyzerV0:
    def __init__(self, registry: ToolRegistry, config: AnalyzerConfig | None = None) -> None:
        self._registry = registry
        self._cfg = config or AnalyzerConfig()
        self._patterns = [re.compile(p, re.IGNORECASE) for p in self._cfg.patterns]

    @property
    def config(self) -> AnalyzerConfig:
        return self._cfg

    def _instruction_score(self, text: str) -> float:
        body = text[:MAX_ITEM_CHARS]
        hits = sum(1 for p in self._patterns if p.search(body))
        return min(1.0, hits / 2)  # one hit = 0.5, two or more = 1.0

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict:
        spec = self._registry.spec(call.tool)
        cfg = self._cfg
        signals: list[str] = []

        # S1: security-relevant value present in untrusted text only
        s1 = 0.0
        prompt_sq = _squash(user_prompt)
        item_sq = [_squash(i.text[:MAX_ITEM_CHARS]) for i in untrusted]
        if spec is not None:
            for name, pspec in spec.params.items():
                if not pspec.security_relevant or pspec.type is ParamType.AMOUNT:
                    continue
                value = _squash(call.args.get(name, ""))
                if value and value not in prompt_sq and any(value in t for t in item_sq):
                    s1 = 1.0
                    signals.append(f"S1:{name}")
                    break

        # S2: instruction-like content anywhere in untrusted context
        item_scores = [self._instruction_score(i.text) for i in untrusted]
        s2 = max(item_scores, default=0.0)
        if s2 > 0:
            signals.append("S2")

        # S3: protected tool not licensed by the prompt wording
        s3 = 0.0
        if spec is not None and spec.protected:
            verbs = cfg.tool_verbs.get(call.tool, ())
            prompt_l = user_prompt.lower()
            if verbs and not any(v in prompt_l for v in verbs):
                s3 = 1.0
                signals.append("S3")

        # S4: the latest untrusted item carried the instruction-like content
        s4 = 1.0 if item_scores and item_scores[-1] > 0 else 0.0
        if s4:
            signals.append("S4")

        # Instruction-like content only matters for calls with side effects: denying a read-only
        # call cannot stop an attack and would only cost utility. Signals stay in the log.
        side_effects = 1.0 if (spec is not None and spec.protected) else 0.0
        score = min(
            1.0,
            cfg.w_provenance * s1
            + side_effects * (cfg.w_instruction * s2 + cfg.w_temporal * s4)
            + cfg.w_alignment * s3,
        )
        decision = Verdict.DENY if score >= cfg.threshold - 1e-9 else Verdict.ALLOW
        return AnalyzerVerdict(
            decision=decision,
            score=round(score, 6),
            signals=tuple(signals),
            version=f"{cfg.version}+{cfg.config_hash}",
        )


V2_TOOL_VERBS: dict[str, tuple[str, ...]] = {
    **DEFAULT_TOOL_VERBS,
    "schedule_transaction": ("schedule", "recurring", "monthly", "rent", "subscription", "bill"),
    "update_scheduled_transaction": (
        "update",
        "adjust",
        "change",
        "rent",
        "scheduled",
        "payment",
        "landlord",
    ),
    "update_password": ("password", "passcode", "credential"),
    "update_user_info": (
        "address",
        "street",
        "city",
        "account information",
        "user info",
        "profile",
    ),
    "reserve_hotel": ("reserve", "book", "booking", "reservation", "hotel", "stay"),
    "reserve_restaurant": ("reserve", "book", "reservation", "restaurant", "table", "dinner"),
    "reserve_car_rental": ("reserve", "book", "rent", "rental", "car"),
    "create_calendar_event": (
        "calendar",
        "event",
        "remind",
        "reminder",
        "schedule",
        "add an event",
    ),
    "cancel_calendar_event": ("cancel", "remove", "delete", "calendar", "event"),
}


class AnalyzerConfigV2(BaseModel):
    """Argument-scoped context analyzer v0.2 (addresses AUD-001 / R-28).

    Key change from v0.1: ``w_instruction + w_temporal = 0.45 < threshold (0.60)``, so untrusted
    instruction text alone never blocks a user-grounded legitimate protected call. Instead, DENY
    requires *either* span-proximal untrusted provenance (``S1_PROX``: a security-relevant argument
    absent from the trusted prompt appears within ``proximity_chars`` of an ``S2`` match) *or*
    tool-intent mismatch (``S3``) combined with injection evidence (``S2``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = "v0.2"
    w_provenance: float = Field(default=0.45, ge=0)
    w_instruction: float = Field(default=0.30, ge=0)
    w_alignment: float = Field(default=0.30, ge=0)
    w_temporal: float = Field(default=0.15, ge=0)
    threshold: float = Field(default=0.60, gt=0, le=1)
    proximity_chars: int = Field(default=250, ge=20, le=5000)
    min_value_chars: int = Field(default=3, ge=1, le=20)
    patterns: tuple[str, ...] = DEFAULT_PATTERNS
    tool_verbs: dict[str, tuple[str, ...]] = Field(default_factory=lambda: dict(V2_TOOL_VERBS))

    @property
    def config_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))[:12]


def _extract_candidate_values(raw: str) -> list[str]:
    """Split comma/JSON-list encoded normalized arguments into individual squashed tokens."""
    stripped = raw.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        parts = stripped[1:-1].split(",")
        return [_squash(p.strip().strip("\"'")) for p in parts if p.strip()]
    return [_squash(stripped)]


class ContextAnalyzerV2:
    """Span-localized provenance + tool-intent alignment analyzer (v0.2)."""

    def __init__(self, registry: ToolRegistry, config: AnalyzerConfigV2 | None = None) -> None:
        self._registry = registry
        self._cfg = config or AnalyzerConfigV2()
        self._patterns = [re.compile(p, re.IGNORECASE) for p in self._cfg.patterns]

    @property
    def config(self) -> AnalyzerConfigV2:
        return self._cfg

    def _scan_item(self, text: str) -> tuple[float, list[str]]:
        body = text[:MAX_ITEM_CHARS]
        hits = 0
        spans: list[tuple[int, int]] = []
        for pattern in self._patterns:
            matched = False
            for m in pattern.finditer(body):
                if not matched:
                    hits += 1
                    matched = True
                spans.append((m.start(), m.end()))
        if not spans:
            return 0.0, []
        pad = self._cfg.proximity_chars
        windows = [_squash(body[max(0, s - pad) : min(len(body), e + pad)]) for s, e in spans]
        return min(1.0, hits / 2), windows

    def analyze(
        self, user_prompt: str, call: NormalizedCall, untrusted: Sequence[ContextItem]
    ) -> AnalyzerVerdict:
        spec = self._registry.spec(call.tool)
        cfg = self._cfg
        signals: list[str] = []

        scanned = [self._scan_item(i.text) for i in untrusted]
        item_scores = [sc for sc, _ in scanned]
        tainted_windows = [win for _, wins in scanned for win in wins]

        # S1_PROX: security-relevant value absent from prompt AND near an injection span
        s1 = 0.0
        prompt_sq = _squash(user_prompt)
        if spec is not None and tainted_windows:
            for name, pspec in spec.params.items():
                if not pspec.security_relevant or pspec.type is ParamType.AMOUNT:
                    continue
                for value in _extract_candidate_values(call.args.get(name, "")):
                    if (
                        len(value) >= cfg.min_value_chars
                        and value not in prompt_sq
                        and any(value in win for win in tainted_windows)
                    ):
                        s1 = 1.0
                        signals.append(f"S1_PROX:{name}")
                        break
                if s1 > 0:
                    break

        # S2: instruction-like content anywhere in untrusted context
        s2 = max(item_scores, default=0.0)
        if s2 > 0:
            signals.append("S2")

        # S3: protected tool not licensed by the prompt wording
        s3 = 0.0
        if spec is not None and spec.protected:
            verbs = cfg.tool_verbs.get(call.tool, ())
            prompt_l = user_prompt.lower()
            if verbs and not any(v in prompt_l for v in verbs):
                s3 = 1.0
                signals.append("S3")

        # S4: latest untrusted item carried instruction-like content
        s4 = 1.0 if item_scores and item_scores[-1] > 0 else 0.0
        if s4:
            signals.append("S4")

        side_effects = 1.0 if (spec is not None and spec.protected) else 0.0
        score = min(
            1.0,
            cfg.w_provenance * s1
            + side_effects * (cfg.w_instruction * s2 + cfg.w_temporal * s4)
            + cfg.w_alignment * s3,
        )
        decision = Verdict.DENY if score >= cfg.threshold - 1e-9 else Verdict.ALLOW
        return AnalyzerVerdict(
            decision=decision,
            score=round(score, 6),
            signals=tuple(signals),
            version=f"{cfg.version}+{cfg.config_hash}",
        )
