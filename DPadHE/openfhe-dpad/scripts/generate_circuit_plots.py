"""Plot the benchmark_circuit results: circuit runtime, RAM footprint and key size."""
import numpy as np

from plot_common import (AXIS_FS, BAR_KW, COLORS, LABELS, LEGEND_FS, TITLE_FS, autolabel, load_csv,
                         numeric_series, save, use_style)
import matplotlib.pyplot as plt

use_style()

df = load_csv("circuit_results.csv")
if df is None:
    raise SystemExit(1)

df = df[df["TaskName"].str.startswith("Circuit")]

task_labels = [f"{t}\n(N={int(n)})" for t, n in zip(df["TaskName"], df["N"])]
x = np.arange(len(df))
width = 0.25


def finite_top(*arrays, factor):
    """Upper y-limit from the finite entries of the given arrays.

    Returns None when nothing is finite, so the axis keeps matplotlib's default
    instead of failing on max([]) or producing an inf limit.
    """
    finite = [v for v in np.concatenate([np.asarray(a, dtype=float) for a in arrays])
              if np.isfinite(v)]
    return max(finite) * factor if finite else None


def bar_set(ax, columns, fmt, normalize=False, headroom=1.2):
    """CKKS-RNS baseline, ModHE and DPad-HE next to each other.

    With normalize=True each group is divided by its CKKS-RNS value, so the bars
    answer "how much slower than the baseline at this depth" and no bar runs off
    the top of the axis.
    """
    data = [numeric_series(df, c).to_numpy() for c in columns]
    if normalize:
        with np.errstate(divide="ignore", invalid="ignore"):
            data = [y / data[0] for y in data]
    for offset, algo, y in zip((-width, 0.0, width), ("RLWE", "Mod", "DPad"), data):
        ax.bar(x + offset, y, width, label=LABELS[algo], color=COLORS[algo], **BAR_KW)
    for rects in ax.containers:
        autolabel(rects, ax, fmt)
    top = finite_top(*data, factor=headroom)
    if top is not None:
        ax.set_ylim(top=top)
    ax.set_xticks(x)
    ax.set_xticklabels(task_labels, fontsize=LEGEND_FS)
    ax.legend(fontsize=LEGEND_FS)


# --- Runtime, normalized to the CKKS-RNS baseline of the same depth ---
fig, ax = plt.subplots(figsize=(10, 6))
bar_set(ax, ("Time_RLWE_ms", "Time_Mod_ms", "Time_DPad_ms"),
        lambda h: f"{h:.2f}x", normalize=True, headroom=1.15)
ax.set_ylabel("Runtime relative to CKKS-RNS", fontsize=AXIS_FS)
ax.set_title("Multiplicative Circuit: Runtime Relative to the CKKS-RNS Baseline",
             fontsize=TITLE_FS, pad=15)
save(fig, "circuit_runtime.png")

# --- Peak RAM ---
fig, ax = plt.subplots(figsize=(10, 6))
bar_set(ax, ("RAM_RLWE_GB", "RAM_Mod_GB", "RAM_DPad_GB"), lambda h: f"{h:.2f}")
ax.set_ylabel("Peak RAM Usage (GB)", fontsize=AXIS_FS)
ax.set_title("Multiplicative Circuit (Depth 6): Memory Footprint", fontsize=TITLE_FS, pad=15)
save(fig, "circuit_ram.png")

# --- Key size (measured) ---
fig, ax = plt.subplots(figsize=(10, 6))
bar_set(ax, ("Key_RLWE_GB", "Key_Mod_GB", "Key_DPad_GB"), lambda h: f"{h:.2f}")
ax.set_ylabel("Evaluation Key Size (GB)", fontsize=AXIS_FS)
ax.set_title("Multiplicative Circuit: Evaluation Key Size (measured)", fontsize=TITLE_FS, pad=15)
save(fig, "circuit_key_size.png")
