"""Dataset manifests (REQ-EVL-5) and cluster-aware splits (docs/research/dataset-selection.md).

A manifest lists every case with its split and carries a SHA-256 over its canonical content, so
any change to the case list, splits, seed or benchmark version is detectable.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agentguard.errors import ConfigError
from agentguard.policy.schemas import canonical_json, sha256_hex

SPLIT_FRACTIONS = (("development", 0.30), ("validation", 0.20), ("test", 0.50))


def assign_split(cluster_id: str, seed: int) -> str:
    """Deterministic split of a *cluster* (user task); all its cases share the split."""
    digest = hashlib.sha256(f"{seed}|{cluster_id}".encode()).digest()
    u = int.from_bytes(digest[:8], "big") / 2**64
    acc = 0.0
    for name, frac in SPLIT_FRACTIONS:
        acc += frac
        if u < acc:
            return name
    return SPLIT_FRACTIONS[-1][0]


class ManifestCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    cluster_id: str  # user task: the unit of splitting and of bootstrap resampling
    scenario_id: str | None = None
    attack_family: str | None = None
    split: str


class Manifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    benchmark: str
    benchmark_version: str
    seed: int
    cases: tuple[ManifestCase, ...] = Field(default_factory=tuple)
    content_hash: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"content_hash"})
        return sha256_hex(canonical_json(body))

    def sealed(self) -> Manifest:
        return self.model_copy(update={"content_hash": self.compute_hash()})

    def verify(self) -> None:
        if not self.content_hash or self.content_hash != self.compute_hash():
            raise ConfigError(f"manifest '{self.name}' was modified or is not sealed")

    def cases_in(self, split: str) -> tuple[ManifestCase, ...]:
        return tuple(c for c in self.cases if c.split == split)


def build_manifest(
    name: str,
    benchmark: str,
    benchmark_version: str,
    seed: int,
    cases: Iterable[tuple[str, str, str | None, str | None]],
) -> Manifest:
    """``cases``: (case_id, cluster_id, scenario_id, attack_family)."""
    built = tuple(
        ManifestCase(
            case_id=cid,
            cluster_id=cl,
            scenario_id=sc,
            attack_family=fam,
            split=assign_split(cl, seed),
        )
        for cid, cl, sc, fam in sorted(set(cases))
    )
    return Manifest(
        name=name, benchmark=benchmark, benchmark_version=benchmark_version, seed=seed, cases=built
    ).sealed()


def save_manifest(path: Path, manifest: Manifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_manifest(path: Path) -> Manifest:
    m = Manifest.model_validate_json(path.read_text(encoding="utf-8"))
    m.verify()
    return m
