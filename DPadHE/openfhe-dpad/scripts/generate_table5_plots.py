"""Plot the benchmark_table5 results: same-depth time and key size (Paper Table 5)."""
import numpy as np

from plot_common import (AXIS_FS, BAR_KW, COLORS, LABELS, LEGEND_FS, TITLE_FS, autolabel, load_csv,
                         note, numeric_series, save, use_style)
import matplotlib.pyplot as plt

use_style()

df = load_csv("table5_results.csv")
if df is None:
    raise SystemExit(1)

df = df.sort_values("Set").reset_index(drop=True)


def series(name):
    return numeric_series(df, name)


x = np.arange(len(df))
w = 0.26
set_labels = [f"Set {s}" for s in df["Set"]]


def bar_set(ax, columns, fmt):
    """One bar triple per set: RNS-CKKS baseline, ModHE, DPad-HE."""
    bars = [
        ax.bar(x - w, series(columns[0]), w, label=LABELS["RLWE"] + " (r = 1)",
               color=COLORS["RLWE"], **BAR_KW),
        ax.bar(x, series(columns[1]), w, label=LABELS["Mod"],
               color=COLORS["Mod"], **BAR_KW),
        ax.bar(x + w, series(columns[2]), w, label=LABELS["DPad"],
               color=COLORS["DPad"], **BAR_KW),
    ]
    for rects in bars:
        autolabel(rects, ax, fmt)
    ax.set_xticks(x)
    ax.set_xticklabels(set_labels)
    ax.legend(fontsize=LEGEND_FS)


def denied_note(ax):
    """Table 5 columns ModHE could not run."""
    refused = [f"Set {s}" for s in df.loc[series("Time_Mod_s").isna(), "Set"]]
    if refused:
        note(ax, "not measured: ModHE for " + ", ".join(refused) + " (RAM guard)")


# --- Table 6: HMult+Rescale time per set ---
fig, ax = plt.subplots(figsize=(10, 6))
bar_set(ax, ("Time_RNS_s", "Time_Mod_s", "Time_DPad_s"), lambda h: f"{h:.2f}")
denied_note(ax)
ax.set_title("HMult+Rescale Time, Same Depth (Paper Table 6)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Parameter Set (Table 5)", fontsize=AXIS_FS)
ax.set_ylabel("Time (s)", fontsize=AXIS_FS)
save(fig, "table5_time_vs_r.png")

# --- Table 7: relinearization key size per set ---
fig, ax = plt.subplots(figsize=(10, 6))
bar_set(ax, ("Key_RNS_MB", "Key_Mod_MB", "Key_DPad_MB"), lambda h: f"{h:.1f}")
denied_note(ax)
ax.set_title("Relinearization Key Size, Same Depth (Paper Table 7)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Parameter Set (Table 5)", fontsize=AXIS_FS)
ax.set_ylabel("Key Size (MB)", fontsize=AXIS_FS)
save(fig, "table5_key_size_vs_r.png")
