"""Exact operating characteristics of the H3 non-inferiority test (M8 plan, section 4).

No Monte Carlo: for each n the rejection region {(a_only, b_only): p < 0.05} is found with the adopted
test (`exact_noninferiority_p`, delta = 0.10, Berger-Boos gamma = 0.005) and the rejection probability is
then summed exactly over the multinomial. Reported: the maximum type I error over the nuisance
(total discordance s) when the true difference is exactly -delta, and the power when the two arms are
truly equal with 5% discordance each way. The same is done for Newcombe's hybrid-score interval, the
rejected alternative, to show why it was rejected.

  python experiments/scripts/m8/h3_operating_characteristics.py docs/research/evidence/m8-h3-operating-characteristics.json
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

from agentguard.evaluation.statistics import exact_noninferiority_p

DELTA, ALPHA = 0.10, 0.05
NS = (9, 30, 60)


def pmf(n: int, a: int, b: int, p10: float, p01: float) -> float:
    rest = 1.0 - p10 - p01
    if rest < -1e-12:
        return 0.0
    rest = max(rest, 0.0)
    k = n - a - b
    out = math.lgamma(n + 1) - math.lgamma(a + 1) - math.lgamma(b + 1) - math.lgamma(k + 1)
    for cnt, p in ((a, p10), (b, p01), (k, rest)):
        if cnt:
            if p <= 0:
                return 0.0
            out += cnt * math.log(p)
    return math.exp(out)


def wilson(k: int, n: int, z: float) -> tuple[float, float]:
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def newcombe_lower(both: int, a: int, b: int, neither: int, z: float) -> float:
    n = both + a + b + neither
    p1, p2 = (both + a) / n, (both + b) / n
    l1, _ = wilson(both + a, n, z)
    _, u2 = wilson(both + b, n, z)
    margins = (both + a, b + neither, both + b, a + neither)
    phi = 0.0
    if all(m > 0 for m in margins):
        phi = (both * neither - a * b) / math.sqrt(math.prod(margins))
    term = (p1 - l1) ** 2 + (u2 - p2) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2)
    return (p1 - p2) - math.sqrt(max(0.0, term))


def region(n: int) -> set[tuple[int, int]]:
    """Discordant counts (a_only, b_only) at which the adopted test rejects H0."""
    return {
        (a, b)
        for a in range(n + 1)
        for b in range(n - a + 1)
        if exact_noninferiority_p(a, b, n, DELTA, grid=60) < ALPHA
    }


def newcombe_region(n: int) -> dict[tuple[int, int, int], bool]:
    """Newcombe needs the full 2x2 table (concordant split matters), so enumerate (both, a, b, neither)."""
    res: dict[tuple[int, int, int], bool] = {}
    for both in range(n + 1):
        for a in range(n - both + 1):
            for b in range(n - both - a + 1):
                res[(both, a, b)] = newcombe_lower(both, a, b, n - both - a - b, 1.644854) > -DELTA
    return res


def adopted_max_type1_and_power(n: int) -> dict[str, float]:
    reg = region(n)
    worst, worst_s = 0.0, 0.0
    for i in range(int(DELTA * 100), 101):
        s = i / 100
        p10 = (s - DELTA) / 2
        p01 = p10 + DELTA
        rej = sum(pmf(n, a, b, p10, p01) for a, b in reg)
        if rej > worst:
            worst, worst_s = rej, s
    power = sum(pmf(n, a, b, 0.05, 0.05) for a, b in reg)
    low_s = max(
        sum(pmf(n, a, b, (s / 100 - DELTA) / 2, (s / 100 - DELTA) / 2 + DELTA) for a, b in reg)
        for s in range(int(DELTA * 100), 31)
    )
    return {"n": n, "max_type1": round(worst, 4), "at_total_discordance": worst_s,
            "max_type1_if_discordance_le_30pct": round(low_s, 4), "power_equal_arms_5pct_each_way": round(power, 4),
            "min_p10_only_pairs_needed_with_no_loss": min((a for a, b in reg if b == 0), default=None)}  # fmt: skip


def newcombe_type1_and_power(n: int) -> dict[str, object]:
    """Maximum type I error of Newcombe's rule, over total discordance s and three concordant mixes."""
    reg = newcombe_region(n)
    # exact calculation over the 4-cell multinomial for a few concordant mixes
    results: dict[str, float] = {}
    for share_both in (0.0, 0.5, 0.9):
        worst, worst_s = 0.0, 0.0
        for i in range(int(DELTA * 100), 101):
            s = i / 100
            p10 = (s - DELTA) / 2
            p01 = p10 + DELTA
            rest = max(0.0, 1.0 - s)
            p11, p00 = rest * share_both, rest * (1 - share_both)
            rej = 0.0
            for (both, a, b), ok in reg.items():
                if not ok:
                    continue
                neither = n - both - a - b
                if (p11 <= 0 and both) or (p00 <= 0 and neither):
                    continue
                lp = math.lgamma(n + 1) - sum(math.lgamma(c + 1) for c in (both, a, b, neither))
                for cnt, p in ((both, p11), (a, p10), (b, p01), (neither, p00)):
                    if cnt:
                        if p <= 0:
                            lp = -math.inf
                            break
                        lp += cnt * math.log(p)
                rej += math.exp(lp) if lp > -math.inf else 0.0
            if rej > worst:
                worst, worst_s = rej, s
        results[f"share_both_{share_both}"] = round(worst, 4)
    return {"n": n, "max_type1_by_concordant_mix": results}


if __name__ == "__main__":
    out_path = Path(sys.argv[1])
    report = {
        "delta": DELTA, "alpha": ALPHA, "berger_boos_gamma": 0.005,
        "adopted_exact_test": [adopted_max_type1_and_power(n) for n in NS],
        "rejected_newcombe_hybrid_score": [newcombe_type1_and_power(n) for n in (9, 30)],
        "note": "exact multinomial sums, no Monte Carlo; type I error is maximised over total discordance s with the true difference exactly -delta",
    }  # fmt: skip
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=1))
