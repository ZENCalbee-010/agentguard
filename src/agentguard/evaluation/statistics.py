"""Statistics for paired binary outcomes (docs/research/research-questions.md section 4).

Pure Python (no numpy) so the core environment stays small. Observations are paired by case key;
repeated runs of one case must be aggregated before testing, never treated as independent.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from agentguard.evaluation.records import ExperimentRecord


def wilson_ci(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n <= 0:
        raise ValueError("n must be positive")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def exact_mcnemar(b: int, c: int) -> float:
    """Two-sided exact p-value from the discordant counts (b: A only, c: B only)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = float(sum(math.comb(n, i) for i in range(k + 1))) / float(2**n)
    return min(1.0, 2.0 * tail)


@dataclass(frozen=True)
class PairedComparison:
    n_pairs: int
    a_only: int  # outcome true in A, false in B
    b_only: int
    both: int
    neither: int
    diff: float  # rate(A) - rate(B)
    p_value: float


def paired_outcomes(
    a: Sequence[ExperimentRecord],
    b: Sequence[ExperimentRecord],
    outcome: Callable[[ExperimentRecord], bool],
    *,
    only_clean: bool = True,
    outcome_b: Callable[[ExperimentRecord], bool] | None = None,
) -> dict[tuple[str, str, int], tuple[bool, bool]]:
    """Pair records of two configurations on (model, case, repetition).

    A pair is dropped (and not silently counted) if either side is unclean or missing, unless
    ``only_clean`` is false. ``outcome_b`` (default: ``outcome``) scores the second side, so a
    sensitivity analysis can impute unclean runs differently in the two arms.
    """
    score_b = outcome if outcome_b is None else outcome_b
    bm = {r.pair_key: r for r in b}
    out: dict[tuple[str, str, int], tuple[bool, bool]] = {}
    for r in a:
        other = bm.get(r.pair_key)
        if other is None or (only_clean and not (r.clean and other.clean)):
            continue
        out[r.pair_key] = (outcome(r), score_b(other))
    return out


def compare_paired(pairs: Mapping[object, tuple[bool, bool]]) -> PairedComparison:
    vals = list(pairs.values())
    n = len(vals)
    if n == 0:
        raise ValueError("no pairs")
    a_only = sum(1 for x, y in vals if x and not y)
    b_only = sum(1 for x, y in vals if y and not x)
    both = sum(1 for x, y in vals if x and y)
    return PairedComparison(
        n, a_only, b_only, both, n - a_only - b_only - both,
        (a_only - b_only) / n, exact_mcnemar(a_only, b_only),
    )  # fmt: skip


def cluster_bootstrap_diff(
    pairs: Mapping[tuple[str, str, int], tuple[bool, bool]],
    cluster_of: Callable[[str], str],
    *,
    resamples: int = 10_000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """CI for rate(A) - rate(B), resampling whole clusters (user tasks), not single cases."""
    clusters: dict[str, list[tuple[bool, bool]]] = {}
    for (_, case_id, _), v in pairs.items():
        clusters.setdefault(cluster_of(case_id), []).append(v)
    keys = sorted(clusters)
    if len(keys) < 2:
        raise ValueError("need at least two clusters")
    rng = random.Random(seed)  # noqa: S311 - seeded for reproducibility, not for security
    diffs = []
    for _ in range(resamples):
        sample = [clusters[rng.choice(keys)] for _ in keys]
        n = sum(len(c) for c in sample)
        d = sum((x > y) - (y > x) for c in sample for x, y in c) / n
        diffs.append(d)
    diffs.sort()
    lo = diffs[int(alpha / 2 * resamples)]
    hi = diffs[min(resamples - 1, int((1 - alpha / 2) * resamples))]
    return lo, hi


def holm_adjust(p_values: Mapping[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (step-down, monotone)."""
    order = sorted(p_values, key=lambda k: p_values[k])
    m = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, key in enumerate(order):
        running = max(running, min(1.0, (m - i) * p_values[key]))
        adjusted[key] = running
    return adjusted


def _cluster_groups(
    pairs: Mapping[tuple[str, str, int], tuple[bool, bool]], cluster_of: Callable[[str], str]
) -> dict[str, list[tuple[bool, bool]]]:
    clusters: dict[str, list[tuple[bool, bool]]] = {}
    for (_, case_id, _), v in pairs.items():
        clusters.setdefault(cluster_of(case_id), []).append(v)
    return clusters


def two_way_bootstrap_diff(
    pairs: Mapping[tuple[str, str, int], tuple[bool, bool]],
    user_of: Callable[[str], str],
    injection_of: Callable[[str], str],
    *,
    resamples: int = 10_000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """CI for rate(A) - rate(B) resampling user tasks and injection tasks independently.

    Sensitivity analysis for crossed dependence (each user task and each injection task recurs).
    A resample keeps every case whose user task AND injection task were both drawn, once per
    combination of draws. Resamples that keep no case are redrawn.
    """
    cell: dict[tuple[str, str], list[tuple[bool, bool]]] = {}
    for (_, case_id, _), v in pairs.items():
        cell.setdefault((user_of(case_id), injection_of(case_id)), []).append(v)
    users = sorted({u for u, _ in cell})
    injs = sorted({i for _, i in cell})
    if len(users) < 2 or len(injs) < 2:
        raise ValueError("need at least two user tasks and two injection tasks")
    rng = random.Random(seed)  # noqa: S311 - seeded for reproducibility, not for security
    diffs: list[float] = []
    while len(diffs) < resamples:
        du = [rng.choice(users) for _ in users]
        di = [rng.choice(injs) for _ in injs]
        kept = [v for u in du for i in di for v in cell.get((u, i), ())]
        if not kept:
            continue
        diffs.append(sum((x > y) - (y > x) for x, y in kept) / len(kept))
    diffs.sort()
    return diffs[int(alpha / 2 * resamples)], diffs[
        min(resamples - 1, int((1 - alpha / 2) * resamples))
    ]


def cluster_sign_test(
    pairs: Mapping[tuple[str, str, int], tuple[bool, bool]], cluster_of: Callable[[str], str]
) -> tuple[int, int, int, float]:
    """Exact two-sided sign test over clusters: each cluster votes by its net discordance.

    Returns (clusters favouring A-only, clusters favouring B-only, tied clusters, p-value).
    Ties (net zero) are not counted. This ignores within-cluster case counts on purpose.
    """
    a_votes = b_votes = ties = 0
    for cases in _cluster_groups(pairs, cluster_of).values():
        net = sum((x > y) - (y > x) for x, y in cases)
        if net > 0:
            a_votes += 1
        elif net < 0:
            b_votes += 1
        else:
            ties += 1
    return a_votes, b_votes, ties, exact_mcnemar(a_votes, b_votes)


def smallest_detectable_one_sided(alpha: float) -> int:
    """Fewest one-direction discordant pairs (none the other way) with exact McNemar p < alpha."""
    b = 1
    while exact_mcnemar(b, 0) >= alpha:
        b += 1
    return b


def _binom_cdf(k: int, n: int, s: float) -> float:
    """P(X <= k) for X ~ Binomial(n, s)."""
    if s <= 0:
        return 1.0
    if s >= 1:
        return 1.0 if k >= n else 0.0
    return min(1.0, sum(math.comb(n, i) * s**i * (1 - s) ** (n - i) for i in range(k + 1)))


def _clopper_pearson(m: int, n: int, gamma: float) -> tuple[float, float]:
    """Exact two-sided (1 - gamma) interval for a binomial probability, by bisection."""
    lo, hi = 0.0, 1.0
    if m > 0:
        a, b = 0.0, m / n
        for _ in range(60):
            mid = (a + b) / 2
            if 1.0 - _binom_cdf(m - 1, n, mid) >= gamma / 2:  # P(X >= m) at mid
                b = mid
            else:
                a = mid
        lo = b
    if m < n:
        a, b = m / n, 1.0
        for _ in range(60):
            mid = (a + b) / 2
            if _binom_cdf(m, n, mid) >= gamma / 2:
                a = mid
            else:
                b = mid
        hi = a
    return lo, hi


def exact_noninferiority_p(
    a_only: int, b_only: int, n: int, delta: float, *, grid: int = 200, gamma: float = 0.005
) -> float:
    """Exact unconditional one-sided p-value for H0: rate(A) - rate(B) <= -delta (paired binary).

    ``a_only``/``b_only`` are the discordant counts out of ``n`` independent pairs (one pair per
    cluster). At the H0 boundary pi10 = pi01 - delta, with the total discordance s = pi10 + pi01 a
    free nuisance parameter. The p-value is max over s of P(A_only - B_only >= observed), where s is
    restricted to its exact (1 - gamma) Clopper-Pearson interval and gamma is added (Berger and
    Boos). This is exact in the multinomial sense (no asymptotics), so it is valid at small n; it
    over-covers slightly because of gamma and grid resolution. A bootstrap and Newcombe's hybrid
    interval were rejected: both over-reject near the boundary (simulation, M8 analysis plan).
    """
    if n <= 0 or a_only < 0 or b_only < 0 or a_only + b_only > n:
        raise ValueError("invalid counts")
    if not 0 < delta < 1:
        raise ValueError("delta must be in (0, 1)")
    observed = a_only - b_only
    s_lo, s_hi = _clopper_pearson(a_only + b_only, n, gamma)
    s_lo = max(s_lo, delta)  # pi01 >= delta under H0
    if s_hi < s_lo:
        return gamma  # no admissible nuisance value: H0 is outside the confidence set
    log_fact = [math.lgamma(k + 1) for k in range(n + 1)]
    worst = 0.0
    for g in range(grid + 1):
        s = s_lo + (s_hi - s_lo) * g / grid
        p10 = (s - delta) / 2
        p01 = p10 + delta
        rest = 1 - s
        if p10 < 0 or rest < 0:
            continue
        logs = (
            math.log(p10) if p10 > 0 else -math.inf,
            math.log(p01),
            math.log(rest) if rest > 0 else -math.inf,
        )
        total = 0.0
        for i in range(n + 1):
            if p10 == 0 and i > 0:
                break
            for j in range(n - i + 1):
                if i - j < observed:
                    continue
                k = n - i - j
                if rest == 0 and k > 0:
                    continue
                lp = log_fact[n] - log_fact[i] - log_fact[j] - log_fact[k]
                lp += (
                    (i * logs[0] if i else 0.0)
                    + (j * logs[1] if j else 0.0)
                    + (k * logs[2] if k else 0.0)
                )
                total += math.exp(lp)
        worst = max(worst, total)
    return min(1.0, worst + gamma)


def exact_noninferiority_margin(a_only: int, b_only: int, n: int, alpha: float = 0.05) -> float:
    """Smallest margin delta at which non-inferiority is established at one-sided level ``alpha``.

    This is the exact one-sided lower confidence bound of rate(A) - rate(B), reported as -delta. It
    is found by bisection; the p-value is non-increasing in delta.
    """
    lo, hi = 0.001, 0.999
    if exact_noninferiority_p(a_only, b_only, n, hi, grid=100) >= alpha:
        return hi
    for _ in range(13):
        mid = (lo + hi) / 2
        if exact_noninferiority_p(a_only, b_only, n, mid, grid=100) < alpha:
            hi = mid
        else:
            lo = mid
    return hi


def exact_binomial_ci(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact (Clopper-Pearson) two-sided 1 - alpha interval for a binomial proportion."""
    if n <= 0 or not 0 <= k <= n:
        raise ValueError("invalid counts")
    return _clopper_pearson(k, n, alpha)
