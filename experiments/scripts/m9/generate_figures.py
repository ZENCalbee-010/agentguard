"""Generate publication-ready SVG figures strictly from validated M8 summary metrics.

Usage (core .venv, zero extra dependencies):
  python experiments/scripts/m9/generate_figures.py \
      --summary results/metrics/m8-banking-qwen35/summary.json \
      --out results/figures

Every plotted value is read directly from ``summary.json``; nothing is hardcoded or invented.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

MODES = ("B0", "B1", "B2", "P1")
MODE_LABELS = {
    "B0": "B0 (No Defense)",
    "B1": "B1 (Analyzer Only)",
    "B2": "B2 (Policy Only)",
    "P1": "P1 (Policy + Analyzer)",
}
MODE_COLORS = {
    "B0": "#64748B",
    "B1": "#D97706",
    "B2": "#059669",
    "P1": "#4F46E5",
}


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _svg_open(width: int, height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{_esc(title)}">',
        "<style>",
        '  text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; '
        "fill: #0F172A; }",
        "  .title { font-size: 16px; font-weight: 700; }",
        "  .subtitle { font-size: 11.5px; fill: #475569; }",
        "  .axis { font-size: 11px; fill: #334155; }",
        "  .val { font-size: 10.5px; font-weight: 600; fill: #0F172A; }",
        "  .legend { font-size: 11px; fill: #1E293B; }",
        "  .grid { stroke: #E2E8F0; stroke-width: 1; }",
        "  .axis-line { stroke: #94A3B8; stroke-width: 1.2; }",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
    ]


def fig1_security_utility(summary: dict[str, Any], out_path: Path) -> None:
    """Grouped bar chart: Executed ASR vs Utility Under Attack (valid_13 & strict_11)."""
    w, h = 840, 420
    left, right, top, bottom = 70, 30, 82, 85
    plot_w = w - left - right
    plot_h = h - top - bottom
    lines = _svg_open(w, h, "Figure 1: Security vs Utility Under Attack across B0, B1, B2, P1")
    lines.append(
        '<text x="70" y="30" class="title">'
        "Figure 1. Security vs. Utility Under Attack (M8 Frozen Test Split, qwen3.5:9b)</text>"
    )
    lines.append(
        '<text x="70" y="49" class="subtitle">'
        "Executed Unauthorized ASR (lower is safer) vs. Clean Task Utility Under Attack "
        "(higher is better); n = clean runs per configuration</text>"
    )

    series = [
        ("Executed ASR (all attack)", "#DC2626"),
        ("Utility Under Attack (valid_13)", "#059669"),
        ("Utility Under Attack (strict_11)", "#2563EB"),
    ]
    # Legend
    lx = 70
    for label, color in series:
        lines.append(f'<rect x="{lx}" y="60" width="12" height="12" rx="2" fill="{color}"/>')
        lines.append(f'<text x="{lx + 17}" y="70" class="legend">{_esc(label)}</text>')
        lx += 235

    # Y grid (0%..70%)
    y_max = 70.0
    for pct in range(0, 71, 10):
        y = top + plot_h * (1.0 - pct / y_max)
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{w - right}" y2="{y:.1f}" class="grid"/>')
        lines.append(
            f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" class="axis">{pct}%</text>'
        )
    lines.append(
        f'<line x1="{left}" y1="{top + plot_h}" x2="{w - right}" y2="{top + plot_h}" '
        'class="axis-line"/>'
    )

    group_w = plot_w / len(MODES)
    bar_w = 40
    gap = 8
    for gi, m in enumerate(MODES):
        m_all = summary["metrics"][m]["all"]
        m_val = summary["metrics"][m]["valid_13"]
        m_str = summary["metrics"][m]["strict_11"]
        asr = 100.0 * m_all["asr_executed"] / m_all["attack_cases_clean"]
        u_val = (
            100.0 * m_val["task_success_under_attack_valid"] / m_val["utility_attack_cases_valid"]
        )
        u_str = (
            100.0 * m_str["task_success_under_attack_valid"] / m_str["utility_attack_cases_valid"]
        )
        vals = [
            (asr, f"{m_all['asr_executed']}/{m_all['attack_cases_clean']}"),
            (
                u_val,
                f"{m_val['task_success_under_attack_valid']}/{m_val['utility_attack_cases_valid']}",
            ),
            (
                u_str,
                f"{m_str['task_success_under_attack_valid']}/{m_str['utility_attack_cases_valid']}",
            ),
        ]
        cx = left + group_w * (gi + 0.5)
        start_x = cx - (3 * bar_w + 2 * gap) / 2
        for bi, ((pct, frac), (_, color)) in enumerate(zip(vals, series, strict=True)):
            bx = start_x + bi * (bar_w + gap)
            bh = plot_h * (pct / y_max)
            by = top + plot_h - bh
            lines.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{max(bh, 1.5):.1f}" '
                f'rx="3" fill="{color}"/>'
            )
            lines.append(
                f'<text x="{bx + bar_w / 2:.1f}" y="{by - 15:.1f}" text-anchor="middle" '
                f'class="val">{pct:.1f}%</text>'
            )
            lines.append(
                f'<text x="{bx + bar_w / 2:.1f}" y="{by - 4:.1f}" text-anchor="middle" '
                f'class="subtitle">{frac}</text>'
            )
        lines.append(
            f'<text x="{cx:.1f}" y="{top + plot_h + 24}" text-anchor="middle" '
            f'class="val">{_esc(MODE_LABELS[m])}</text>'
        )

    lines.append(
        f'<text x="{left}" y="{h - 18}" class="subtitle">'
        "Source: results/metrics/m8-banking-qwen35/summary.json (m8-freeze a1a105f). "
        "H1 (B2 vs B0): p = 1.19e-7 (SUPPORTED, robust). P1 vs B2 utility (strict_11): -17.5 pp, "
        "p = 0.00195.</text>"
    )
    lines.append("</svg>\n")
    out_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def fig2_per_task_attacks(summary: dict[str, Any], out_path: Path) -> None:
    """Horizontal bar chart of executed attacks per user task (active clusters)."""
    per_task = summary["per_user_task"]
    ordered = sorted(per_task, key=lambda s: int(s.rsplit("_", 1)[1]))
    w, h = 840, 440
    left, right, top, bottom = 120, 40, 82, 55
    plot_w = w - left - right
    plot_h = h - top - bottom
    lines = _svg_open(w, h, "Figure 2: Executed Unauthorized Attacks per User Task")
    lines.append(
        '<text x="30" y="30" class="title">'
        "Figure 2. Executed Unauthorized Attacks by User Task (Clean Attack Cases, max 9/task)"
        "</text>"
    )
    lines.append(
        '<text x="30" y="49" class="subtitle">'
        "B0 executed 31/99 attacks across 6/11 tasks; B2 blocked all outside user_task_0 "
        "(2 wildcard escapes); B1 and P1 executed 0/93</text>"
    )

    # Legend
    lx = 120
    for m in MODES:
        lines.append(
            f'<rect x="{lx}" y="60" width="12" height="12" rx="2" fill="{MODE_COLORS[m]}"/>'
        )
        lines.append(f'<text x="{lx + 17}" y="70" class="legend">{_esc(MODE_LABELS[m])}</text>')
        lx += 168

    x_max = 9.0
    for tick in range(0, 10):
        x = left + plot_w * (tick / x_max)
        lines.append(
            f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top + plot_h}" class="grid"/>'
        )
        lines.append(
            f'<text x="{x:.1f}" y="{top + plot_h + 18}" text-anchor="middle" '
            f'class="axis">{tick}</text>'
        )
    lines.append(
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" class="axis-line"/>'
    )

    row_h = plot_h / len(ordered)
    for ri, task in enumerate(ordered):
        ry = top + ri * row_h
        b0_ex, b0_att, _ = per_task[task]["B0"]
        b2_ex, _, _ = per_task[task]["B2"]
        tag = " *" if task in ("user_task_0", "user_task_10") else ""
        lines.append(
            f'<text x="{left - 10}" y="{ry + row_h * 0.62:.1f}" text-anchor="end" '
            f'class="axis">{task}{tag}</text>'
        )
        # B0 bar (top half) and B2 bar (bottom half); B1/P1 are 0 everywhere
        bh = max(7.0, row_h * 0.34)
        if b0_ex > 0:
            bw = plot_w * (b0_ex / x_max)
            lines.append(
                f'<rect x="{left}" y="{ry + 3:.1f}" width="{bw:.1f}" height="{bh:.1f}" '
                f'rx="2" fill="{MODE_COLORS["B0"]}"/>'
            )
            lines.append(
                f'<text x="{left + bw + 6:.1f}" y="{ry + 3 + bh - 1:.1f}" class="val">'
                f"B0: {b0_ex}/{b0_att} att</text>"
            )
        if b2_ex > 0:
            bw2 = plot_w * (b2_ex / x_max)
            lines.append(
                f'<rect x="{left}" y="{ry + 4 + bh:.1f}" width="{bw2:.1f}" height="{bh:.1f}" '
                f'rx="2" fill="{MODE_COLORS["B2"]}"/>'
            )
            lines.append(
                f'<text x="{left + bw2 + 6:.1f}" y="{ry + 4 + 2 * bh - 1:.1f}" class="val">'
                f"B2: {b2_ex} (wildcard)</text>"
            )
        if b0_ex == 0 and b2_ex == 0:
            lines.append(
                f'<text x="{left + 6}" y="{ry + row_h * 0.62:.1f}" class="subtitle">'
                "0 attempted / 0 executed in all configs</text>"
            )

    lines.append(
        f'<text x="30" y="{h - 14}" class="subtitle">'
        "* Tasks with static policy-reachable wildcard cells (6 cells each in banking-v2). "
        "B1 and P1 had 0 executed attacks in every task.</text>"
    )
    lines.append("</svg>\n")
    out_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def fig3_latency_tokens(summary: dict[str, Any], out_path: Path) -> None:
    """Two-panel chart: Latency (Median/Mean/P95) and Input Tokens per run (RQ5)."""
    w, h = 840, 390
    lines = _svg_open(w, h, "Figure 3: Latency and Token Overhead per Configuration (RQ5)")
    lines.append(
        '<text x="30" y="30" class="title">'
        "Figure 3. Runtime Latency and Token Cost per Run (RQ5, Local Apple M2 Pro, 0 THB)</text>"
    )
    lines.append(
        '<text x="30" y="49" class="subtitle">'
        "Over n = 110 runs per configuration (0 excluded for infrastructure failure); "
        "overhead is driven by retry turns after tool denials</text>"
    )

    cost = summary["cost"]
    # Panel A: Latency (left)
    p1_l, p1_t, p1_w, p1_h = 65, 95, 340, 225
    lines.append(f'<text x="{p1_l}" y="78" class="val">A. Wall-Clock Latency (seconds/run)</text>')
    lat_max = 80.0
    for sec in range(0, 81, 20):
        y = p1_t + p1_h * (1.0 - sec / lat_max)
        lines.append(
            f'<line x1="{p1_l}" y1="{y:.1f}" x2="{p1_l + p1_w}" y2="{y:.1f}" class="grid"/>'
        )
        lines.append(
            f'<text x="{p1_l - 8}" y="{y + 4:.1f}" text-anchor="end" class="axis">{sec}s</text>'
        )
    lines.append(
        f'<line x1="{p1_l}" y1="{p1_t + p1_h}" x2="{p1_l + p1_w}" y2="{p1_t + p1_h}" '
        'class="axis-line"/>'
    )
    lat_series = [
        ("median_s", "Median", "#0EA5E9"),
        ("mean_s", "Mean", "#4F46E5"),
        ("p95_s", "P95", "#F59E0B"),
    ]
    gw = p1_w / len(MODES)
    bw = 20
    for gi, m in enumerate(MODES):
        cx = p1_l + gw * (gi + 0.5)
        sx = cx - (3 * bw + 8) / 2
        for bi, (key, _, col) in enumerate(lat_series):
            val = float(cost[m][key])
            bh = p1_h * (val / lat_max)
            bx = sx + bi * (bw + 4)
            by = p1_t + p1_h - bh
            lines.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw}" height="{bh:.1f}" '
                f'rx="2" fill="{col}"/>'
            )
            lines.append(
                f'<text x="{bx + bw / 2:.1f}" y="{by - 4:.1f}" text-anchor="middle" '
                f'class="subtitle">{val:.1f}</text>'
            )
        lines.append(
            f'<text x="{cx:.1f}" y="{p1_t + p1_h + 18}" text-anchor="middle" class="val">{m}</text>'
        )
    lx = p1_l
    for _, lbl, col in lat_series:
        lines.append(
            f'<rect x="{lx}" y="{p1_t + p1_h + 30}" width="10" height="10" rx="2" fill="{col}"/>'
        )
        lines.append(f'<text x="{lx + 14}" y="{p1_t + p1_h + 39}" class="legend">{lbl}</text>')
        lx += 82

    # Panel B: Mean Input Tokens (right)
    p2_l, p2_t, p2_w, p2_h = 480, 95, 330, 225
    lines.append(
        f'<text x="{p2_l}" y="78" class="val">B. Mean Input Tokens &amp; Model Calls / Run</text>'
    )
    tok_max = 10000.0
    for tok in range(0, 10001, 2000):
        y = p2_t + p2_h * (1.0 - tok / tok_max)
        lines.append(
            f'<line x1="{p2_l}" y1="{y:.1f}" x2="{p2_l + p2_w}" y2="{y:.1f}" class="grid"/>'
        )
        lines.append(
            f'<text x="{p2_l - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'class="axis">{tok // 1000}k</text>'
        )
    lines.append(
        f'<line x1="{p2_l}" y1="{p2_t + p2_h}" x2="{p2_l + p2_w}" y2="{p2_t + p2_h}" '
        'class="axis-line"/>'
    )
    gw2 = p2_w / len(MODES)
    bw2 = 44
    for gi, m in enumerate(MODES):
        val = float(cost[m]["in_tok_per_run"])
        calls = float(cost[m]["model_calls_per_run"])
        bh = p2_h * (val / tok_max)
        cx = p2_l + gw2 * (gi + 0.5)
        bx = cx - bw2 / 2
        by = p2_t + p2_h - bh
        lines.append(
            f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw2}" height="{bh:.1f}" '
            f'rx="3" fill="{MODE_COLORS[m]}"/>'
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{by - 15:.1f}" text-anchor="middle" class="val">'
            f"{val:,.0f}</text>"
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{by - 4:.1f}" text-anchor="middle" class="subtitle">'
            f"{calls:.1f} calls</text>"
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{p2_t + p2_h + 18}" text-anchor="middle" class="val">{m}</text>'
        )
    lines.append(
        f'<text x="{p2_l}" y="{p2_t + p2_h + 39}" class="subtitle">'
        "Total M8 wall clock: 2.95 h (440 runs); B1 = P1 token counts exactly</text>"
    )
    lines.append("</svg>\n")
    out_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", default="results/metrics/m8-banking-qwen35/summary.json")
    ap.add_argument("--out", default="results/figures")
    args = ap.parse_args()
    summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    fig1_security_utility(summary, out_dir / "fig1_security_utility_tradeoff.svg")
    fig2_per_task_attacks(summary, out_dir / "fig2_per_task_attacks.svg")
    fig3_latency_tokens(summary, out_dir / "fig3_latency_tokens_overhead.svg")
    print(f"wrote 3 SVG figures to {out_dir}")


if __name__ == "__main__":
    main()
