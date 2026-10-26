"""Plot the benchmark_relin_breakdown results: relinearization phase breakdown."""
import numpy as np

from plot_common import (AXIS_FS, BAR_KW, COLORS, LEGEND_FS, TITLE_FS, autolabel, label_total,
                         load_csv, note, numeric_series, save, use_style)
import matplotlib.pyplot as plt

use_style()

df = load_csv("relin_breakdown_results.csv")
if df is None:
    raise SystemExit(1)

ranks = df["Rank"]
x = np.arange(len(ranks))
mod_full = numeric_series(df, "ModHE_Relin_ms")
mod_down = numeric_series(df, "ModHE_RankDown_ms")
dpad_down = numeric_series(df, "DPad_RankDown_ms")
dpad_up = numeric_series(df, "DPad_RankUp_ms")


def denied_note(ax):
    if mod_full.isna().any():
        r_stop = int(ranks[mod_full.isna()].min())
        note(ax, f"not measured: ModHE from r = {r_stop} (RAM guard)")


# --- Stacked phases: ModHE full relin vs DPad rank-down + rank-up ---
fig, ax = plt.subplots(figsize=(10, 6))
width = 0.35
ax.bar(x - width / 2, mod_full, width, label="ModHE (full relin)",
       color=COLORS["Mod"], **BAR_KW)
ax.bar(x + width / 2, dpad_down, width, label="DPad-HE (rank-down)",
       color=COLORS["DPad"], **BAR_KW)
ax.bar(x + width / 2, dpad_up, width, bottom=dpad_down.fillna(0),
       label="DPad-HE (rank-up)", color=COLORS["DPadLight"], **BAR_KW)
autolabel(ax.containers[0], ax, lambda h: f"{h:.0f}")
# One label for the whole DPad stack: the two phases share a bar, so a label per
# phase would sit on top of each other wherever a phase is short.
label_total(ax, x + width / 2, (dpad_down.fillna(0) + dpad_up.fillna(0)).to_numpy(),
            lambda h: f"{h:.0f}")
denied_note(ax)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Runtime (ms)", fontsize=AXIS_FS)
ax.set_title("Relinearization Pipeline: ModHE vs DPad-HE", fontsize=TITLE_FS, pad=15)
ax.set_xticks(x)
ax.set_xticklabels(ranks)
ax.legend(fontsize=LEGEND_FS)
save(fig, "relin_components.png")

# --- RankDown isolation ---
fig, ax = plt.subplots(figsize=(8, 6))
ax.plot(ranks, mod_down, marker="s", color=COLORS["Mod"], label="ModHE (rank-down)",
        linewidth=2, markersize=8)
ax.plot(ranks, dpad_down, marker="o", color=COLORS["DPad"], label="DPad-HE (rank-down)",
        linewidth=2, markersize=8)
denied_note(ax)
ax.set_title("RankDown Phase: ModHE vs DPad-HE", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Runtime (ms)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "rankdown_comparison.png")
