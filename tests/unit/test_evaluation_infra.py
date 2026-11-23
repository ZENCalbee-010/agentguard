"""Records, metrics, statistics, manifests and configs (M6).

Includes AC-M6-01: metrics recomputed from the committed raw M5 smoke records equal the figures in
docs/milestones/M5-report.md.
"""

from __future__ import annotations

import glob
import json
import math
from pathlib import Path
from typing import Any

import pytest

from agentguard.errors import ConfigError
from agentguard.evaluation.config import ExperimentConfig, load_config
from agentguard.evaluation.manifest import (
    SPLIT_FRACTIONS,
    assign_split,
    build_manifest,
    load_manifest,
    save_manifest,
)
from agentguard.evaluation.metrics import compute_metrics, metrics_by_config
from agentguard.evaluation.records import (
    ExperimentRecord,
    export_csv,
    from_smoke_dict,
    missing_cases,
    read_records,
    write_records,
)
from agentguard.evaluation.statistics import (
    cluster_bootstrap_diff,
    compare_paired,
    exact_mcnemar,
    holm_adjust,
    paired_outcomes,
    wilson_ci,
)

ROOT = Path(__file__).resolve().parents[2]
SMOKE = sorted(glob.glob(str(ROOT / "results" / "raw" / "m5-smoke" / "*.jsonl")))
DENY_ATTEMPT = {
    "step": 1,
    "tool": "t",
    "verdict": "DENY",
    "reasons": ["NO_CAPABILITY"],
    "executed": False,
}


def smoke_records() -> list[ExperimentRecord]:
    lines = Path(SMOKE[0]).read_text(encoding="utf-8").splitlines()
    return [from_smoke_dict(json.loads(line), "m5-smoke") for line in lines if line]


def synth(
    mode: str,
    case: str,
    *,
    attack: bool = True,
    executed: bool = False,
    success: bool = True,
    status: str = "completed",
    denied: bool = False,
) -> ExperimentRecord:
    return ExperimentRecord.model_validate(
        {
            "experiment_id": "x",
            "run_id": f"{mode}{case}",
            "case_id": case,
            "task_id": case.split(":")[0],
            "scenario_id": case if attack else None,
            "benchmark": "b",
            "benchmark_version": "1",
            "model": {"model_id": "m"},
            "config_id": mode,
            "policy_hash": "h",
            "seed": 0,
            "attack_attempted": True if attack else None,
            "attack_executed": executed if attack else None,
            "task_success": success,
            "run_status": status,
            "latency_s": 1.0,
            "input_tokens": 1,
            "output_tokens": 1,
            "model_calls": 1,
            "tool_attempts": [DENY_ATTEMPT] if denied else [],
        }
    )


# ---- AC-M6-01: recompute from stored evidence ---------------------------------------------
@pytest.mark.skipif(not SMOKE, reason="raw smoke records not present")
def test_ac_m6_01_metrics_recomputed_from_raw_records_match_the_m5_report() -> None:
    recs = smoke_records()
    assert len(recs) == 124 and all(r.code_dirty is False for r in recs)
    m = metrics_by_config(recs)
    executed = {mode: m[("qwen3:8b", mode)]["asr_executed"] for mode in ("B0", "B1", "B2", "P1")}
    assert executed == {"B0": 14, "B1": 2, "B2": 4, "P1": 2}
    assert {k[1]: v["attempted"] for k, v in m.items()} == {"B0": 14, "B1": 14, "B2": 14, "P1": 14}
    under_attack = {k[1]: v["task_success_under_attack"] for k, v in m.items()}
    assert under_attack == {"B0": 8, "B1": 10, "B2": 18, "P1": 10}
    assert all(v["benign_success"] == 11 and v["benign_cases_with_denial"] == 0 for v in m.values())
    assert all(v["attack_cases_clean"] == 20 and v["attack_cases_unclean"] == 0 for v in m.values())


@pytest.mark.skipif(not SMOKE, reason="raw smoke records not present")
def test_real_paired_comparison_b0_vs_b2() -> None:
    recs = smoke_records()
    b0 = [r for r in recs if r.config_id == "B0" and r.is_attack]
    b2 = [r for r in recs if r.config_id == "B2" and r.is_attack]
    cmp = compare_paired(paired_outcomes(b0, b2, lambda r: bool(r.attack_executed)))
    assert cmp.n_pairs == 20 and cmp.a_only - cmp.b_only == 10
    assert cmp.p_value == exact_mcnemar(cmp.a_only, cmp.b_only) < 0.01


# ---- records ---------------------------------------------------------------------------------
@pytest.mark.skipif(not SMOKE, reason="raw smoke records not present")
def test_roundtrip_missing_cases_and_csv(tmp_path: Path) -> None:
    recs = smoke_records()
    path = tmp_path / "r.jsonl"
    assert write_records(path, recs) == 124 and read_records(path) == recs
    expected = {(r.model.model_id, r.config_id, r.case_id, 0) for r in recs}
    assert missing_cases(expected, recs) == []
    assert len(missing_cases(expected, recs[:-3])) == 3  # an interrupted run is visible
    assert export_csv(tmp_path / "r.csv", recs) == 124
    header, first = (tmp_path / "r.csv").read_text(encoding="utf-8").splitlines()[:2]
    assert "attack_executed" in header and "qwen3:8b" in first


def test_strict_read_rejects_corrupt_or_extra_fields(tmp_path: Path) -> None:
    good = synth("B0", "a:x").model_dump_json()
    for bad in (good[:-5], good.replace('"seed":0', '"seed":0,"surprise":1')):
        p = tmp_path / "bad.jsonl"
        p.write_text(bad + "\n", encoding="utf-8")
        with pytest.raises(ValueError):
            read_records(p)


# ---- metrics: denominators and exclusion of unclean runs -----------------------------------------
def test_unclean_runs_are_excluded_from_numerator_and_denominator_and_counted() -> None:
    recs = [
        synth("B0", "a:1", executed=True),
        synth("B0", "a:2", executed=False),
        synth("B0", "a:3", executed=True, status="step_limit"),  # would inflate ASR if counted
        synth("B0", "a:4", status="model_timeout"),
        synth("B0", "b:1", attack=False, success=True),
        synth("B0", "b:2", attack=False, success=False, status="context_overflow"),
    ]
    m = compute_metrics(recs)
    assert (m["attack_cases_clean"], m["attack_cases_unclean"]) == (2, 2)
    assert m["asr_executed"] == 1
    assert (m["benign_cases_clean"], m["benign_cases_unclean"], m["benign_success"]) == (1, 1, 1)


def test_false_negative_and_denial_counts() -> None:
    recs = [
        synth("P1", "a:1", executed=True),
        synth("P1", "a:2", denied=True),
        synth("P1", "b:1", attack=False, denied=True),
    ]
    m = compute_metrics(recs)
    assert m["fn_executed_given_attempt"] == 1 and m["attempted"] == 2
    assert m["benign_cases_with_denial"] == 1 and m["denials_by_reason"] == {"NO_CAPABILITY": 2}


# ---- statistics ----------------------------------------------------------------------------------
def test_wilson_and_mcnemar_known_values() -> None:
    lo, hi = wilson_ci(11, 11)
    assert round(lo, 2) == 0.74 and hi == pytest.approx(1.0)
    lo, hi = wilson_ci(8, 11)
    assert (round(lo, 2), round(hi, 2)) == (0.43, 0.90)
    assert exact_mcnemar(0, 0) == 1.0 and exact_mcnemar(5, 5) == 1.0
    assert exact_mcnemar(8, 2) == pytest.approx(0.109375)
    assert exact_mcnemar(10, 0) == pytest.approx(2 / 1024)
    with pytest.raises(ValueError):
        wilson_ci(0, 0)


def test_holm_is_monotone_and_matches_hand_calculation() -> None:
    adj = holm_adjust({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == {"a": pytest.approx(0.03), "c": pytest.approx(0.06), "b": pytest.approx(0.06)}


def test_pairing_drops_unclean_and_unmatched_pairs_instead_of_counting_them() -> None:
    a = [
        synth("B0", "a:1", executed=True),
        synth("B0", "a:2", executed=True, status="step_limit"),
        synth("B0", "a:3", executed=True),
    ]
    b = [synth("B2", "a:1"), synth("B2", "a:2")]  # a:3 missing on the B2 side
    pairs = paired_outcomes(a, b, lambda r: bool(r.attack_executed))
    assert list(pairs.values()) == [(True, False)]


def _cluster(case_id: str) -> str:
    return case_id.split(":")[0]


def test_cluster_bootstrap_is_deterministic_and_respects_clusters() -> None:
    pairs = {("m", f"t{c}:{i}", 0): (True, False) for c in range(8) for i in range(5)}
    assert cluster_bootstrap_diff(pairs, _cluster, resamples=500, seed=1) == (1.0, 1.0)
    mixed = {("m", f"t{c}:{i}", 0): (c % 2 == 0, False) for c in range(8) for i in range(5)}
    a = cluster_bootstrap_diff(mixed, _cluster, resamples=500, seed=7)
    assert a == cluster_bootstrap_diff(mixed, _cluster, resamples=500, seed=7)
    assert 0.0 < a[0] < 0.5 < a[1] < 1.0  # wide: only 8 clusters, not 40 independent cases
    with pytest.raises(ValueError):
        cluster_bootstrap_diff({("m", "t:1", 0): (True, False)}, _cluster)


def test_identical_configurations_give_a_null_comparison() -> None:
    pairs = {("m", f"c{i}", 0): (i % 3 == 0, i % 3 == 0) for i in range(30)}
    cmp = compare_paired(pairs)
    assert cmp.diff == 0 and cmp.p_value == 1.0
    assert cluster_bootstrap_diff(pairs, lambda c: c, resamples=200, seed=0) == (0.0, 0.0)


# ---- manifests ------------------------------------------------------------------------------------
def test_split_is_deterministic_cluster_level_and_roughly_proportional() -> None:
    assert assign_split("task-1", 7) == assign_split("task-1", 7)
    counts = {n: 0 for n, _ in SPLIT_FRACTIONS}
    for i in range(2000):
        counts[assign_split(f"t{i}", 3)] += 1
    for name, frac in SPLIT_FRACTIONS:
        assert abs(counts[name] / 2000 - frac) < 0.04
    assert len({assign_split("t5", s) for s in range(30)}) > 1  # the seed matters


def test_manifest_seal_verify_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    cases = [(f"{t}|{s}", t, s, "override") for t in ("t1", "t2", "t3", "t4") for s in ("s1", "s2")]
    m = build_manifest("n", "own", "v1", 1, cases)
    by_cluster: dict[str, set[str]] = {}
    for c in m.cases:
        by_cluster.setdefault(c.cluster_id, set()).add(c.split)
    assert all(len(v) == 1 for v in by_cluster.values())  # a cluster never spans two splits
    path = tmp_path / "m.json"
    save_manifest(path, m)
    assert load_manifest(path) == m
    with pytest.raises(ConfigError):
        m.model_copy(update={"content_hash": ""}).verify()
    with pytest.raises(ConfigError):
        m.model_copy(update={"seed": 2}).verify()
    moved = m.cases[0].model_copy(
        update={"split": "validation" if m.cases[0].split != "validation" else "test"}
    )
    with pytest.raises(ConfigError):
        m.model_copy(update={"cases": (moved, *m.cases[1:])}).verify()


# ---- config ----------------------------------------------------------------------------------------
def _cfg(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "experiment_id": "e1",
        "benchmark": "own",
        "benchmark_version": "v1",
        "manifest_path": "m.json",
        "manifest_hash": "x",
        "models": [{"name": "qwen3:8b", "think": False}],
    }
    return {**base, **over}


def test_config_validation(tmp_path: Path) -> None:
    ok = ExperimentConfig.model_validate(_cfg())
    assert [c.value for c in ok.configs] == ["B0", "B1", "B2", "P1"] and ok.api_budget_thb == 0
    assert ok.config_hash == ExperimentConfig.model_validate(_cfg()).config_hash
    assert ok.config_hash != ExperimentConfig.model_validate(_cfg(repetitions=2)).config_hash
    bad_configs = (
        _cfg(enforce=False),
        _cfg(configs=["B0", "B0"]),
        _cfg(configs=[]),
        _cfg(split="all"),
        _cfg(models=[{"name": "m", "bypass": True}]),
        _cfg(api_budget_thb=-1),
    )
    for bad in bad_configs:
        with pytest.raises(ValueError):
            ExperimentConfig.model_validate(bad)
    (tmp_path / "c.yaml").write_text("experiment_id: e\nbenchmark: o\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "c.yaml")


def test_config_must_match_the_sealed_manifest() -> None:
    m = build_manifest("n", "own", "v1", 1, [("a|b", "a", "b", None)])
    cfg = ExperimentConfig.model_validate(_cfg(manifest_hash=m.content_hash))
    cfg.check_manifest(m)
    wrong_hash = ExperimentConfig.model_validate(_cfg(manifest_hash="0" * 64))
    with pytest.raises(ConfigError):
        wrong_hash.check_manifest(m)
    wrong_version = ExperimentConfig.model_validate(
        _cfg(manifest_hash=m.content_hash, benchmark_version="v2")
    )
    with pytest.raises(ConfigError):
        wrong_version.check_manifest(m)
    assert math.isfinite(cfg.max_wall_s)


def test_utility_exclusion_changes_only_the_utility_counts() -> None:
    recs = [
        synth(
            "B0", "user_task_5:x", executed=True, success=True
        ),  # attack, utility passes trivially
        synth("B0", "user_task_1:x", executed=True, success=False),
        synth("B0", "user_task_5:benign", attack=False, success=True),
        synth("B0", "user_task_1:benign", attack=False, success=False),
    ]
    all_ = compute_metrics(recs)
    valid = compute_metrics(recs, frozenset({"user_task_5"}))
    assert all_["asr_executed"] == valid["asr_executed"] == 2  # security never excludes cases
    assert (all_["task_success_under_attack"], all_["benign_success"]) == (1, 1)
    assert (valid["utility_attack_cases_valid"], valid["task_success_under_attack_valid"]) == (1, 0)
    assert (valid["utility_benign_cases_valid"], valid["benign_success_valid"]) == (1, 0)
    assert all_["utility_attack_cases_valid"] == 2  # default excludes nothing


# ---- additional pre-registered statistics (M8 analysis plan) ---------------------------------------
def test_sign_test_two_way_and_detectability() -> None:
    from agentguard.evaluation.statistics import (
        cluster_sign_test,
        smallest_detectable_one_sided,
        two_way_bootstrap_diff,
    )

    def user(case: str) -> str:
        return case.split("|")[0]

    def inj(case: str) -> str:
        return case.split("|")[1]

    mixed = {("m", f"u{u}|i{i}", 0): (u % 2 == 0, True) for u in range(6) for i in range(3)}
    votes = {
        ("m", "u0|i0", 0): (True, False), ("m", "u1|i0", 0): (True, False),
        ("m", "u2|i0", 0): (True, False), ("m", "u3|i0", 0): (False, True),
        ("m", "u4|i0", 0): (True, True),
    }  # fmt: skip
    assert cluster_sign_test(votes, user)[:3] == (3, 1, 1)
    assert cluster_sign_test(votes, user)[3] == pytest.approx(0.625)  # exact two-sided, n=4, k=1

    plus = {("m", f"u{u}|i{i}", 0): (True, False) for u in range(4) for i in range(3)}
    assert two_way_bootstrap_diff(plus, user, inj, resamples=200, seed=2) == (1.0, 1.0)
    assert two_way_bootstrap_diff(
        mixed, user, inj, resamples=200, seed=3
    ) == two_way_bootstrap_diff(mixed, user, inj, resamples=200, seed=3)
    with pytest.raises(ValueError):
        two_way_bootstrap_diff({("m", "u0|i0", 0): (True, False)}, user, inj)

    assert smallest_detectable_one_sided(0.05) == 6  # 2 * 0.5**b < alpha
    assert smallest_detectable_one_sided(0.05 / 3) == 7


def test_exact_noninferiority() -> None:
    from agentguard.evaluation.statistics import exact_noninferiority_margin, exact_noninferiority_p

    # nine concordant pairs cannot show non-inferiority within 10 points
    assert exact_noninferiority_p(0, 0, 9, 0.10) > 0.05
    # many concordant pairs can; the floor is the Berger-Boos gamma
    assert exact_noninferiority_p(0, 0, 100, 0.10) == pytest.approx(0.005)
    # A losing clearly more often than B can never show it
    assert exact_noninferiority_p(0, 5, 20, 0.10) > 0.5
    # more evidence with the same pattern -> smaller or equal p
    assert exact_noninferiority_p(0, 0, 60, 0.10) <= exact_noninferiority_p(0, 0, 30, 0.10)
    # a larger margin is easier
    assert exact_noninferiority_p(0, 0, 30, 0.20) < exact_noninferiority_p(0, 0, 30, 0.10)
    # the smallest establishable margin shrinks with n, grows with observed losses
    m9, m60 = exact_noninferiority_margin(0, 0, 9), exact_noninferiority_margin(0, 0, 60)
    assert m60 < m9
    assert 0.2 < m9 < 0.5
    assert exact_noninferiority_margin(0, 1, 9) > m9
    # consistency with the p-value (bisection tolerance 2**-13)
    assert exact_noninferiority_p(0, 0, 9, m9 + 0.01, grid=100) < 0.05
    assert exact_noninferiority_p(0, 0, 9, m9 - 0.02, grid=100) >= 0.05
    with pytest.raises(ValueError):
        exact_noninferiority_p(5, 5, 4, 0.1)
    with pytest.raises(ValueError):
        exact_noninferiority_p(0, 0, 10, 0.0)


def test_exact_binomial_ci_known_values() -> None:
    from agentguard.evaluation.statistics import exact_binomial_ci

    lo, hi = exact_binomial_ci(0, 12)  # rule of three: upper bound 1 - 0.025**(1/12)
    assert lo == 0.0 and hi == pytest.approx(1 - 0.025 ** (1 / 12), abs=1e-6)
    lo, hi = exact_binomial_ci(12, 12)
    assert hi == 1.0 and lo == pytest.approx(0.025 ** (1 / 12), abs=1e-6)
    lo, hi = exact_binomial_ci(5, 10)  # standard table value: 0.1871 to 0.8129
    assert lo == pytest.approx(0.1871, abs=1e-3) and hi == pytest.approx(0.8129, abs=1e-3)
    with pytest.raises(ValueError):
        exact_binomial_ci(3, 2)


def test_paired_outcomes_can_score_the_two_arms_differently() -> None:
    a = [synth("B0", "u:1", executed=True, status="step_limit"), synth("B0", "u:2", executed=False)]
    b = [synth("B2", "u:1", executed=False), synth("B2", "u:2", executed=False)]
    # default: the unclean pair is dropped
    assert len(paired_outcomes(a, b, lambda r: bool(r.attack_executed))) == 1
    # unclean counted as executed ONLY in the second (treated) arm and as not executed in the first
    pairs = paired_outcomes(
        a, b, lambda r: r.clean and bool(r.attack_executed), only_clean=False,
        outcome_b=lambda r: (not r.clean) or bool(r.attack_executed),
    )  # fmt: skip
    assert pairs[("m", "u:1", 0)] == (False, False)
    # the reverse imputation makes the unclean reference-arm run favour the defence, which is the
    # asymmetry that a same-lambda-for-both-arms bound would have produced
    swapped = paired_outcomes(
        a, b, lambda r: (not r.clean) or bool(r.attack_executed), only_clean=False,
        outcome_b=lambda r: r.clean and bool(r.attack_executed),
    )  # fmt: skip
    assert swapped[("m", "u:1", 0)] == (True, False)
