"""Shared helpers for the DPad-HE benchmark plots."""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Paths and style
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
PLOTS_DIR = os.path.join(BASE_DIR, "..", "plots")

COLORS = {"RLWE": "#2ca02c", "Mod": "#1f77b4", "DPad": "#ff7f0e", "DPadLight": "#ffbb78"}
LABELS = {"RLWE": "CKKS-RNS", "Mod": "ModHE", "DPad": "DPad-HE"}
MARKERS = {"RLWE": "^", "Mod": "s", "DPad": "o"}
ALGOS = ("RLWE", "Mod", "DPad")

# One style for every figure: solid is measured, dashed is the paper value,
# dotted is the RAM guard's analytic estimate. Only the paper line carries a
# marker, so a dotted line is never read as a measurement.
PAPER_KW = dict(linestyle="--", linewidth=2, markersize=8, alpha=0.6)
ESTIMATE_KW = dict(linestyle=":", linewidth=2, alpha=0.6)

# For figures whose series are operations, not schemes: no colour of its own,
# so that colour stays reserved for the scheme.
NEUTRAL_COLORS = ("#4d4d4d", "#9e9e9e")

# Bar appearance, shared by every bar figure. Give this dict
# edgecolor="black" and all bars get an outline.
BAR_KW = dict(edgecolor="none", linewidth=1.2)

TITLE_FS = 14
AXIS_FS = 12
LEGEND_FS = 11
NOTE_FS = 10


def use_style():
    plt.style.use("seaborn-v0_8-whitegrid")


def autolabel(rects, ax, fmt):
    """Write fmt(value) above every bar; a denied bar (NaN) gets nothing."""
    for rect in rects:
        h = rect.get_height()
        if h != h or np.isinf(h):
            continue
        top = rect.get_y() + h  # a stacked segment sits on its bottom segment
        ax.annotate(fmt(h), xy=(rect.get_x() + rect.get_width() / 2, top),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=NOTE_FS)


def label_total(ax, xs, values, fmt):
    """One label above a whole stack, instead of one per segment."""
    for x, value in zip(xs, values):
        if value != value or np.isinf(value):  # NaN or inf
            continue
        ax.annotate(fmt(value), xy=(x, value), xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=NOTE_FS)


def note(ax, text, loc="upper left"):
    """One grey line inside the axes, for data the figure cannot show."""
    x, ha = (0.02, "left") if "left" in loc else (0.98, "right")
    y, va = (0.98, "top") if "upper" in loc else (0.02, "bottom")
    ax.text(x, y, text, transform=ax.transAxes, ha=ha, va=va,
            fontsize=NOTE_FS, color="0.35")


def load_csv(name):
    """Load a results CSV, or return None with a message if it is missing."""
    path = os.path.join(RESULTS_DIR, name)
    if not os.path.exists(path):
        print(f"Error: {name} not found in {RESULTS_DIR}")
        return None
    return pd.read_csv(path)


def numeric_series(df, column):
    """One column as floats; every non-measurement becomes NaN."""
    series = pd.to_numeric(df[column], errors="coerce")
    series = series.replace([np.inf, -np.inf], np.nan)
    return series.mask(series < 0)


def normalized_to_first(series):
    """series / series[first valid], for a 'relative to rank 2' axis."""
    valid = series.dropna()
    if valid.empty:
        return series
    return series / valid.iloc[0]


def save(fig, filename):
    os.makedirs(PLOTS_DIR, exist_ok=True)
    out = os.path.join(PLOTS_DIR, filename)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"wrote {os.path.relpath(out, BASE_DIR)}")
