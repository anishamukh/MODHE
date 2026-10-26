"""Plot the benchmark_precision results: worst-case precision vs module rank."""
import numpy as np

from plot_common import (AXIS_FS, COLORS, LABELS, LEGEND_FS, MARKERS, TITLE_FS,
                         load_csv, note, numeric_series, save, use_style)
import matplotlib.pyplot as plt

use_style()

df = load_csv("precision_results.csv")
if df is None:
    raise SystemExit(1)

# Fixed window so the two precision figures stay comparable; it only grows if a
# measured value leaves it.
PREC_YMIN, PREC_YMAX = 31, 37

# Paper Sec. 5 precision condition, indexed by the ring dimension that runs the
# chain. The paper reports no value for N = 2^14.
PAPER_TARGET = {32768: 33.9, 65536: 33.4}


# The RNS-CKKS curve is left out of the precision figures on purpose: the figure
# is read against the paper's target, and a third curve that behaves like the other
# two invites the question of what it is doing there. The values stay in the CSV and
# in the comparison table.
PRECISION_ALGOS = ("Mod", "DPad")


def plot_series(sub, title, filename):
    df_rank = sub.sort_values("r")
    fig, ax = plt.subplots(figsize=(8, 6))
    y_lo, y_hi = PREC_YMIN, PREC_YMAX
    target = [PAPER_TARGET.get(int(n), float("nan")) for n in df_rank["N_RLWE"]]
    missing = []
    for algo in PRECISION_ALGOS:
        y = numeric_series(df_rank, f"Prec_{algo}")
        if len(y):
            y_lo, y_hi = min(y_lo, y.min() - 2), max(y_hi, y.max() + 2)
            if y.isna().any():
                missing.append(f"{LABELS[algo]} from r = {int(df_rank.loc[y.isna(), 'r'].min())}")
        ax.plot(df_rank["r"], y, marker=MARKERS[algo], color=COLORS[algo],
                label=f"{LABELS[algo]} (OpenFHE estimate)", linewidth=2, markersize=8)
    ax.plot(df_rank["r"], target, marker="s", linestyle="--", color="0.45",
            linewidth=2, markersize=8, alpha=0.6, label="Precision (Paper, Sec. 5, at N = r x n)")
    if missing:
        note(ax, "not measured: " + ", ".join(missing) + " (RAM guard)", loc="lower left")
    ax.set_title(title, fontsize=TITLE_FS, pad=15)
    ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
    ax.set_ylabel("Precision (bits)", fontsize=AXIS_FS)
    ax.set_ylim(y_lo, y_hi)
    ax.set_xticks(np.arange(2, 9, 1))
    ax.legend(fontsize=LEGEND_FS)
    save(fig, filename)


series_a = df[df["TestName"].str.startswith("Paper_Scale")]
if not series_a.empty:
    plot_series(series_a, "Precision vs Rank, Paper Table 3 (L grows with r)",
                "precision_vs_rank_paper.png")

series_b = df[df["TestName"].str.startswith("FixedL30")]
if not series_b.empty:
    plot_series(series_b, "Precision vs Rank, fixed L=30 (rank effect only)",
                "precision_vs_rank_fixedL.png")
