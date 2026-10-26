"""Plot the benchmark_hmult_rescale results: key size and runtime vs module rank."""
import numpy as np

from plot_common import (ALGOS, AXIS_FS, COLORS, ESTIMATE_KW, LABELS, LEGEND_FS, MARKERS,
                         NEUTRAL_COLORS, PAPER_KW, TITLE_FS, load_csv, normalized_to_first, note,
                         numeric_series, save, use_style)
import matplotlib.pyplot as plt

use_style()

df = load_csv("hmult_rescale_results.csv")
if df is None:
    raise SystemExit(1)

df = df[df["TestName"].str.startswith("Paper_Scale")]
df_rank = df.sort_values("r")

key_meas = {a: numeric_series(df_rank, f"Key_{a}_GB") for a in ALGOS}
key_est = {a: numeric_series(df_rank, f"KeyEst_{a}_GB") for a in ALGOS}
time_relin = {a: numeric_series(df_rank, f"Time_{a}_ms") for a in ALGOS}
time_block = {a: numeric_series(df_rank, f"Time_{a}_hmult_rescale_ms") for a in ALGOS}
ram = {a: numeric_series(df_rank, f"RAM_{a}_GB") for a in ALGOS}

RANK_TICKS = list(range(2, 9))


def denied_note(ax, series_by_algo):
    """One grey line for every scheme the RAM guard refused."""
    missing = []
    for algo, y in series_by_algo.items():
        if y.notna().any() and y.isna().any():
            r_stop = int(df_rank.loc[y.isna(), "r"].min())
            missing.append(f"{LABELS[algo]} from r = {r_stop}")
    if missing:
        note(ax, "not measured: " + ", ".join(missing) + " (RAM guard)")


# --- Key size vs rank ---
fig, ax = plt.subplots(figsize=(8, 6))
for algo in ALGOS:
    ax.plot(df_rank["r"], key_meas[algo], marker=MARKERS[algo], color=COLORS[algo],
            label=LABELS[algo] + " (measured)", linewidth=2, markersize=8)
    ax.plot(df_rank["r"], key_est[algo], color=COLORS[algo],
            label=LABELS[algo] + " (estimated)", **ESTIMATE_KW)
ax.set_title("Relinearization Key Size vs Rank (N = 8192)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_xticks(RANK_TICKS)
ax.set_ylabel("Key Size (GB)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "key_size_vs_rank.png")

# --- HMult+Rescale runtime vs rank, with paper overlay ---
fig, ax = plt.subplots(figsize=(8, 6))
for algo in ALGOS:
    y = normalized_to_first(time_block[algo])
    if y.notna().any():
        ax.plot(df_rank["r"], y, marker=MARKERS[algo], color=COLORS[algo],
                label=LABELS[algo] + " (measured)", linewidth=2, markersize=8)

paper_r = [2, 3, 4, 5, 6, 7, 8]
paper_mod_time = [49, 242, 772, 2049, 5676, 8173, 19060]
paper_dpad_time = [39, 124, 325, 737, 1328, 2066, 3337]
ax.plot(paper_r, [t / paper_mod_time[0] for t in paper_mod_time], marker="s",
        color=COLORS["Mod"], label=LABELS["Mod"] + " (Paper)", **PAPER_KW)
ax.plot(paper_r, [t / paper_dpad_time[0] for t in paper_dpad_time], marker="o",
        color=COLORS["DPad"], label=LABELS["DPad"] + " (Paper)", **PAPER_KW)
denied_note(ax, time_block)

ax.set_xticks(RANK_TICKS)
ax.set_title("HMult+Rescale vs Rank (N = 8192)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Normalized Runtime (to rank 2)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "hmult_rescale_vs_rank.png")

# --- Relinearization runtime vs rank ---
fig, ax = plt.subplots(figsize=(8, 6))
for algo in ALGOS:
    y = normalized_to_first(time_relin[algo])
    if y.notna().any():
        ax.plot(df_rank["r"], y, marker=MARKERS[algo], color=COLORS[algo],
                label=LABELS[algo], linewidth=2, markersize=8)
denied_note(ax, time_relin)
ax.set_xticks(RANK_TICKS)
ax.set_title("Relinearization Runtime vs Rank (N = 8192)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Normalized Runtime (to rank 2)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "relin_runtime_vs_rank.png")

# --- Speedup over the whole block, measured against the paper's Speedup row ---
# The relinearization alone carries 86-99 % of the block, so its ratio says the
# same thing; the comparison that matters here is ours against the paper.
PAPER_R = list(range(2, 9))
PAPER_SPEEDUP = [1.26, 1.95, 2.37, 2.78, 4.27, 3.95, 5.71]

fig, ax = plt.subplots(figsize=(8, 6))
speedup = numeric_series(df_rank, "Speedup_HMultRescale")
ax.plot(df_rank["r"], speedup, marker="o", color=NEUTRAL_COLORS[0],
        label="ModHE / DPad-HE (measured)", linewidth=2, markersize=8)
ax.plot(PAPER_R, PAPER_SPEEDUP, marker="s", color=NEUTRAL_COLORS[0],
        label="ModHE / DPad-HE (Paper)", **PAPER_KW)
ax.axhline(1.0, color="grey", linestyle=":", linewidth=1.5)
denied_note(ax, {"Mod": speedup})
ax.set_xticks(RANK_TICKS)
ax.set_title("Speedup ModHE / DPad-HE vs Rank (N = 8192)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Speedup (ModHE / DPad-HE)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "speedup_vs_rank.png")

# --- Peak RAM vs rank ---
fig, ax = plt.subplots(figsize=(8, 6))
for algo in ALGOS:
    y = ram[algo]
    if y.notna().any():
        ax.plot(df_rank["r"], y, marker=MARKERS[algo], color=COLORS[algo],
                label=LABELS[algo], linewidth=2, markersize=8)
denied_note(ax, ram)
ax.set_xticks(RANK_TICKS)
ax.set_title("Peak RAM vs Rank (N = 8192)", fontsize=TITLE_FS, pad=15)
ax.set_xlabel("Module Rank (r)", fontsize=AXIS_FS)
ax.set_ylabel("Peak RAM (GB)", fontsize=AXIS_FS)
ax.legend(fontsize=LEGEND_FS)
save(fig, "ram_vs_rank.png")
