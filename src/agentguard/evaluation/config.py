"""Experiment configuration schema (REQ-EVL-1, SEC-014).

The schema has no field that can disable enforcement or change a configuration's behaviour
beyond its ``GatewayMode``; unknown keys are rejected.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.errors import ConfigError
from agentguard.evaluation.manifest import Manifest
from agentguard.policy.schemas import GatewayMode, canonical_json, sha256_hex


class ModelSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    num_ctx: int = Field(default=8192, ge=512)
    think: bool | None = None
    temperature: float = Field(default=0.0, ge=0)
    seed: int = 0
    max_output_tokens: int = Field(default=1024, ge=16)


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    experiment_id: str
    description: str = ""
    benchmark: str
    benchmark_version: str
    manifest_path: str
    manifest_hash: str  # must equal the sealed manifest's content hash
    split: str = "development"
    models: tuple[ModelSpec, ...]
    configs: tuple[GatewayMode, ...] = tuple(GatewayMode)
    repetitions: int = Field(default=1, ge=1)
    max_steps: int = Field(default=10, ge=1)
    max_wall_s: float = Field(default=300.0, gt=0)
    analyzer_config_hash: str | None = None
    policy_version: str | None = None  # benchmark policy set (e.g. banking-v1); None if not used
    api_budget_thb: float = Field(default=0.0, ge=0)  # no paid calls without approval (REQ-GOV-1)

    @field_validator("configs")
    @classmethod
    def _unique_nonempty(cls, v: tuple[GatewayMode, ...]) -> tuple[GatewayMode, ...]:
        if not v or len(set(v)) != len(v):
            raise ValueError("configs must be non-empty and unique")
        return v

    @field_validator("split")
    @classmethod
    def _known_split(cls, v: str) -> str:
        if v not in ("development", "validation", "test"):
            raise ValueError("split must be development, validation or test")
        return v

    def check_manifest(self, manifest: Manifest) -> None:
        """Refuse to run against a manifest that is not exactly the one the config froze."""
        manifest.verify()
        if manifest.content_hash != self.manifest_hash:
            raise ConfigError("manifest hash does not match the experiment config")
        if (manifest.benchmark, manifest.benchmark_version) != (
            self.benchmark,
            self.benchmark_version,
        ):
            raise ConfigError("manifest benchmark/version does not match the experiment config")

    @property
    def config_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


def load_config(path: Path) -> ExperimentConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return ExperimentConfig.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f"invalid experiment config {path}: {exc}") from exc
