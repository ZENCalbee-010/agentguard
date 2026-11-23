"""The committed pilot protocol, manifest and analyzer configuration must agree with each other."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.defense.context_analyzer import AnalyzerConfig
from agentguard.errors import ConfigError
from agentguard.evaluation.config import load_config
from agentguard.evaluation.manifest import load_manifest

ROOT = Path(__file__).resolve().parents[2]


def test_pilot_config_matches_the_sealed_manifest_and_analyzer() -> None:
    cfg = load_config(ROOT / "experiments" / "configs" / "m7-pilot.yaml")
    manifest = load_manifest(ROOT / cfg.manifest_path)
    cfg.check_manifest(manifest)
    assert cfg.analyzer_config_hash == AnalyzerConfig().config_hash
    assert cfg.split == "development" and cfg.api_budget_thb == 0
    assert len(manifest.cases_in("development")) == 30  # 3 clusters x (9 attacks + 1 benign)


def test_pilot_uses_only_the_development_split_clusters() -> None:
    manifest = load_manifest(ROOT / "datasets" / "manifests" / "banking-v1.json")
    dev = {c.cluster_id for c in manifest.cases_in("development")}
    other = {c.cluster_id for s in ("validation", "test") for c in manifest.cases_in(s)}
    assert dev == {"user_task_2", "user_task_7", "user_task_15"} and not dev & other


def test_editing_the_manifest_hash_in_the_config_is_detected() -> None:
    cfg = load_config(ROOT / "experiments" / "configs" / "m7-pilot.yaml")
    tampered = cfg.model_copy(update={"manifest_hash": "0" * 64})
    with pytest.raises(ConfigError):
        tampered.check_manifest(load_manifest(ROOT / cfg.manifest_path))


def test_m8_config_is_the_frozen_test_split_protocol() -> None:
    """M8 differs from the qwen3.5 pilot only in the split (and ids): same model, settings, policies."""
    m8 = load_config(ROOT / "experiments" / "configs" / "m8-banking-qwen35.yaml")
    pilot = load_config(ROOT / "experiments" / "configs" / "m7c-pilot-qwen35.yaml")
    manifest = load_manifest(ROOT / m8.manifest_path)
    m8.check_manifest(manifest)
    assert m8.split == "test" and m8.api_budget_thb == 0 and m8.repetitions == 1
    assert m8.analyzer_config_hash == AnalyzerConfig().config_hash
    assert m8.policy_version == "banking-v2"
    assert m8.models == pilot.models and not m8.models[0].think
    for field in (
        "configs",
        "max_steps",
        "max_wall_s",
        "manifest_hash",
        "benchmark_version",
        "policy_version",
    ):
        assert getattr(m8, field) == getattr(pilot, field), field
    cases = manifest.cases_in("test")
    assert len(cases) == 110 and len(cases) * len(m8.configs) == 440
    assert len({c.cluster_id for c in cases}) == 11
    assert sum(1 for c in cases if c.scenario_id is None) == 11  # one benign case per user task


def test_m8_analysis_constants_are_pinned() -> None:
    """The pre-registered constants live in the analysis script; changing them must trip this test."""
    src = (ROOT / "experiments" / "scripts" / "m8" / "analyze_main.py").read_text(encoding="utf-8")
    for needle in (
        "SEED = 20261119", "RESAMPLES = 10_000", "ALPHA = 0.05", "DELTA = 0.10",
        'PRIMARY_STRATUM = "valid_13"', "EXPOSURE_MIN_ATTEMPTS = 10", "EXPOSURE_MIN_CLUSTERS = 4",
        'MODES = ("B0", "B1", "B2", "P1")',
    ):  # fmt: skip
        assert needle in src, needle
    plan = (ROOT / "docs" / "research" / "m8-analysis-plan.md").read_text(encoding="utf-8")
    for needle in (
        "delta = 10 percentage points",
        "20261119",
        "at least **10**",
        "at least **4** user tasks",
    ):
        assert needle in plan, needle


def test_m8b_noise_config_is_b0_only_and_otherwise_identical() -> None:
    m8 = load_config(ROOT / "experiments" / "configs" / "m8-banking-qwen35.yaml")
    noise = load_config(ROOT / "experiments" / "configs" / "m8b-noise-b0.yaml")
    noise.check_manifest(load_manifest(ROOT / noise.manifest_path))
    assert [m.value for m in noise.configs] == ["B0"] and noise.experiment_id != m8.experiment_id
    for field in (
        "models",
        "split",
        "max_steps",
        "max_wall_s",
        "manifest_hash",
        "policy_version",
        "analyzer_config_hash",
    ):
        assert getattr(noise, field) == getattr(m8, field), field
