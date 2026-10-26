"""
Compare the measured benchmark CSVs against the numbers published in the DPad
paper, and print a claim-by-claim verdict.

Usage:
    python3 compare_with_paper.py              # terminal report
    python3 compare_with_paper.py --csv out    # also write a machine-readable CSV
    python3 compare_with_paper.py --latex out  # also write LaTeX (booktabs) tables

Paper values are transcribed from library/DPad-HE-paper.pdf, Table 4 (RQ1),
Table 6 and Table 7 (RQ2). Table 8 (GPU) and Table 9 (MLWE-RLWE conversion) are
out of scope: no GPU on the test host, and the conversion is not part of this
thesis. The precision target (~33.9 bits at N = 2^15, Sec. 5) has no table; it is
reported for the precision run instead. Note that the target is the average
decryption error of the paper's own implementation, while the measured column is
OpenFHE's error estimate, so the verdict on that row is indicative.
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")

# ---------------------------------------------------------------------------
# Paper values (transcribed from the PDF)
# ---------------------------------------------------------------------------

# Table 4 (RQ1), n = 2^13: HMult+Rescale time in seconds and key size in MB.
TABLE4 = {
    "r":      [2, 3, 4, 5, 6, 7, 8],
    "ModHE_s": [0.049, 0.242, 0.772, 2.049, 5.676, 8.173, 19.06],
    "DPad_s":  [0.039, 0.124, 0.325, 0.737, 1.328, 2.066, 3.337],
    "Speedup": [1.26, 1.95, 2.37, 2.78, 4.27, 3.95, 5.71],
    "ModHE_MB": [35, 210, 859, 2559, 5874, 11970, 23388],
    "DPad_MB":  [24, 106, 344, 793, 1696, 2758, 5234],
}

# Table 6 (RQ2), same mult. depth: time in seconds. RNS-CKKS is r = 1.
# key: (N, r) -> (RNS_s, ModHE_s, DPad_s)
TABLE6 = {
    (2**15, 1): (0.301, None, None),
    (2**15, 2): (None, 0.429, 0.317),
    (2**15, 4): (None, 0.772, 0.325),
    (2**16, 1): (2.482, None, None),
    (2**16, 2): (None, 3.718, 1.99),
    (2**16, 4): (None, 6.645, 2.03),
}

# Table 7 (RQ2), same mult. depth: key size in MB.
# key: (N, r) -> (RNS_MB, ModHE_MB, DPad_MB)
TABLE7 = {
    (2**15, 1): (137.5, None, None),
    (2**15, 2): (None, 309.4, 166.9),
    (2**15, 4): (None, 859.4, 343.8),
    (2**16, 1): (1155.0, None, None),
    (2**16, 2): (None, 2598.75, 1214.3),
    (2**16, 4): (None, 7218.7, 2010.9),
}

# RQ2 fairness condition (Sec. 5): precision saturates near 33.9 bits at N = r*n = 2^15
# and 33.4 bits at 2^16. Keyed by the ring dimension that runs the chain, because
# that is the dimension the paper states its condition for. The paper measures the
# average decryption error; the column compared here is OpenFHE's error estimate,
# so the two numbers differ in kind and the verdict is indicative.
PRECISION_TARGET = {2**15: 33.9, 2**16: 33.4}


def load(name):
    path = os.path.join(RESULTS_DIR, name)
    if not os.path.exists(path):
        print(f"  (missing: {name})")
        return None
    return pd.read_csv(path)


def num(df, col):
    """One column as floats with every non-measurement masked to NaN.

    Denied runs are written as -1.0 sentinels by the benchmarks; they must never
    enter a comparison, exactly as they must never enter a plot.
    """
    series = pd.to_numeric(df[col], errors="coerce")
    series = series.replace([np.inf, -np.inf], np.nan)
    return series.mask(series < 0)


def cell(value):
    """Format a possibly-NaN measured value, spelling out a denied run."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "denied"
    return f"{value:8.3f}"


def verdict(measured, paper, rel_tol=0.20):
    """Classify a measured/paper pair against a relative tolerance."""
    if measured is None or paper is None:
        return "n/a"
    if np.isnan(measured):
        return "denied"
    ratio = measured / paper
    if abs(ratio - 1.0) <= rel_tol:
        return f"ok ({ratio:.2f}x)"
    return f"OFF ({ratio:.2f}x)"


def section(title):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def compare_table4(hmult):
    section("Table 4 (RQ1) - HMult+Rescale time, key size, speedup")
    if hmult is None:
        return []
    rows = []
    df = hmult[hmult["TestName"].str.startswith("Paper_Scale")].copy()
    df["r"] = pd.to_numeric(df["r"], errors="coerce")
    df = df.sort_values("r")
    print(f"{'r':>3} | {'ModHE s (meas/paper)':>24} | {'DPad s (meas/paper)':>24} | {'speedup (meas/paper)':>24}")
    for _, row in df.iterrows():
        r = int(row["r"])
        if r not in TABLE4["r"]:
            continue
        i = TABLE4["r"].index(r)
        m_mod = num(df, "Time_Mod_hmult_rescale_ms").loc[row.name] / 1000.0
        m_dpad = num(df, "Time_DPad_hmult_rescale_ms").loc[row.name] / 1000.0
        m_speed = num(df, "Speedup_HMultRescale").loc[row.name]
        p_mod, p_dpad, p_speed = TABLE4["ModHE_s"][i], TABLE4["DPad_s"][i], TABLE4["Speedup"][i]
        print(f"{r:>3} | {cell(m_mod):>8} / {p_mod:8.3f} {verdict(m_mod, p_mod):>10} "
              f"| {cell(m_dpad):>8} / {p_dpad:8.3f} {verdict(m_dpad, p_dpad):>10} "
              f"| {cell(m_speed):>8} / {p_speed:8.2f} {verdict(m_speed, p_speed):>10}")
        rows.append({"Table": 4, "r_or_set": r, "quantity": "ModHE_s",
                     "measured": m_mod, "paper": p_mod, "verdict": verdict(m_mod, p_mod)})
        rows.append({"Table": 4, "r_or_set": r, "quantity": "DPad_s",
                     "measured": m_dpad, "paper": p_dpad, "verdict": verdict(m_dpad, p_dpad)})
        rows.append({"Table": 4, "r_or_set": r, "quantity": "Speedup",
                     "measured": m_speed, "paper": p_speed, "verdict": verdict(m_speed, p_speed)})
    print()
    print("Note: 'ModHE n/a' from rank 7 means the RAM guard denied the run (11.5 GB at r=6 is the ceiling).")
    return rows


def compare_table5(table5):
    section("Table 6 / Table 7 (RQ2) - same-depth time and key size")
    if table5 is None:
        print("  (no table5_results.csv - run benchmark_table5 first)")
        return []
    rows = []
    df = table5.copy()
    print(f"{'set':>4} | {'N':>7} | {'r':>2} | {'DPad s (meas/paper)':>24} | {'DPad MB (meas/paper)':>24}")
    for _, row in df.iterrows():
        N = int(row["n_RLWE"]); r = int(row["r"])
        key = (N, r)
        p6 = TABLE6.get(key, (None, None, None))
        p7 = TABLE7.get(key, (None, None, None))
        m_dpad_s = pd.to_numeric(pd.Series([row.get("Time_DPad_s")]), errors="coerce").iloc[0]
        m_dpad_mb = pd.to_numeric(pd.Series([row.get("Key_DPad_MB")]), errors="coerce").iloc[0]
        is_denied = pd.isna(m_dpad_s) or m_dpad_s < 0
        if is_denied:
            m_dpad_s = m_dpad_mb = np.nan
        p_s = p6[2] if r != 1 else p6[0]
        p_mb = p7[2] if r != 1 else p7[0]
        print(f"{row['Set']:>4} | {N:>7} | {r:>2} | {cell(m_dpad_s):>8} / {str(p_s):>8} "
              f"| {cell(m_dpad_mb):>8} / {str(p_mb):>8}")
        if p_s is not None:
            rows.append({"Table": 6, "r_or_set": row["Set"], "quantity": "DPad_s",
                         "measured": m_dpad_s, "paper": p_s, "verdict": verdict(m_dpad_s, p_s)})
        if p_mb is not None:
            rows.append({"Table": 7, "r_or_set": row["Set"], "quantity": "DPad_MB",
                         "measured": m_dpad_mb, "paper": p_mb, "verdict": verdict(m_dpad_mb, p_mb)})
    return rows


def _min_column(df, column):
    """Smallest non-negative value of one CSV column, or None if there is none."""
    vals = [pd.to_numeric(pd.Series([row.get(column)]), errors="coerce").iloc[0]
            for _, row in df.iterrows()]
    vals = [v for v in vals if pd.notna(v) and v >= 0]
    return min(vals) if vals else None


def compare_precision(prec):
    section("RQ2 precision condition (Sec. 5) - target 33.9 bits at N = r*n = 2^15, "
            "33.4 bits at 2^16")
    if prec is None:
        return []
    rows = []
    df = prec[prec["TestName"].str.startswith("Paper_Scale")].copy()
    if df.empty:
        df = prec.copy()
    # The paper states its precision condition for the RNS-CKKS ring dimension
    # N = r*n. The RLWE column is measured at exactly that dimension, so it is the
    # column the target compares against.
    for dim, target in sorted(PRECISION_TARGET.items()):
        sel = df[pd.to_numeric(df["N_RLWE"], errors="coerce") == dim]
        measured = _min_column(sel, "Prec_RLWE")
        if measured is None:
            continue
        power = int(np.log2(dim))
        print(f"  N_RLWE = 2^{power}: min precision {measured:.2f} bits (RLWE column, OpenFHE estimate)")
        print(f"  target (paper Sec. 5, same ring dimension): {target:.1f} bits")
        print("  note: target = paper's average decryption error; measured = OpenFHE estimate")
        rows.append({"Table": "Sec.5", "r_or_set": f"$N = 2^{{{power}}}$", "quantity": "min Precision",
                     "measured": measured, "paper": target,
                     "verdict": "ok" if abs(measured - target) <= 3 else "OFF"})
    # The MLWE schemes run at n = 2^13 (Paper Table 3), where the paper states no
    # precision target. Reported ungraded, so the number is not silently dropped.
    for algo in ("Mod", "DPad"):
        measured = _min_column(df, f"Prec_{algo}")
        if measured is not None:
            print(f"  {algo}HE at n = 2^13 (no paper target): min precision {measured:.2f} bits")
    return rows


def _tex_value(value, digits=3):
    """A measured value as a LaTeX cell; a denied run is spelled out."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "denied"
    return f"{value:.{digits}f}"


def _tex_verdict(text):
    """Verdict text for a LaTeX cell (kept symbolic, no math mode)."""
    return text.replace("_", r"\_")


def write_latex(rows, path):
    """Write the comparison as tabular fragments a thesis chapter can \\input.

    One table per paper table, booktabs style. The measured and paper columns sit
    side by side with the verdict as a third column, so a claim reads as one row
    instead of two numbers the reader has to line up by hand.
    """
    import collections

    by_table = collections.OrderedDict()
    for row in rows:
        by_table.setdefault(row["Table"], []).append(row)

    captions = {
        4: ("Comparison of HMult+Rescale time and speedup against Table~4 (RQ1).",
            "tab:compare-table4"),
        6: ("Comparison of same-depth evaluation time against Table~6 (RQ2).",
            "tab:compare-table6"),
        7: ("Comparison of same-depth key size against Table~7 (RQ2).",
            "tab:compare-table7"),
        "Sec.5": ("Minimum precision of the RNS-CKKS column (OpenFHE's error estimate) on the paper's ring "
                  "dimension N = r x n, next to the RQ2 target (Sec.~5). The target is the average decryption "
                  "error of the paper's implementation, so the two numbers differ in kind and the verdict is "
                  "indicative.",
                  "tab:compare-precision"),
    }
    fallback = lambda table: (f"Comparison against Table~{table}.",
                              f"tab:compare-{str(table).lower().replace('.', '')}")

    lines = [
        "% Generated by scripts/compare_with_paper.py --latex.",
        "% Booktabs required: \\usepackage{booktabs}.",
        "% Each block is a standalone table; cut out the ones you need.",
        "",
    ]
    for table, table_rows in by_table.items():
        caption, label = captions.get(table, fallback(table))
        lines.append(r"\begin{table}[htbp]")
        lines.append(r"  \centering")
        lines.append(f"  \\caption{{{caption}}}")
        lines.append(f"  \\label{{{label}}}")
        lines.append(r"  \begin{tabular}{l l r r l}")
        lines.append(r"    \toprule")
        lines.append(r"    Quantity & Set & Measured & Paper & Verdict \\")
        lines.append(r"    \midrule")
        for row in table_rows:
            digits = 2 if row["quantity"] == "Speedup" else 3
            lines.append(
                f"    {_tex_verdict(row['quantity'])} & {row['r_or_set']} & "
                f"{_tex_value(row['measured'], digits)} & "
                f"{_tex_value(row['paper'], digits)} & "
                f"{_tex_verdict(row['verdict'])} \\\\"
            )
        lines.append(r"    \bottomrule")
        lines.append(r"  \end{tabular}")
        lines.append(r"\end{table}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print()
    print("wrote", path)


def main():
    ap = argparse.ArgumentParser(description="Compare measured CSVs against the DPad paper tables.")
    ap.add_argument("--csv", metavar="PATH", help="also write the comparison rows to a CSV file")
    ap.add_argument("--latex", metavar="PATH", help="also write the comparison as LaTeX tables")
    args = ap.parse_args()

    print("Measured values are read from", os.path.abspath(RESULTS_DIR))

    hmult = load("hmult_rescale_results.csv")
    rows = []
    rows += compare_table4(hmult)
    rows += compare_table5(load("table5_results.csv"))
    rows += compare_precision(load("precision_results.csv"))

    section("Not covered")
    print("  RQ3, Table 8 (GPU)         : no GPU OpenFHE backend on the test host")
    print("  RQ4, Fig. 3 (all levels)   : benchmark_circuit covers it in shape only")
    print("  RQ5, Fig. 4 (rotation)     : not implemented")
    print("  RQ6, Table 9 (MLWE<->RLWE) : conversion outside the scope of this thesis")

    if args.csv and rows:
        pd.DataFrame(rows).to_csv(args.csv, index=False)
        print()
        print("wrote", args.csv)

    if args.latex and rows:
        write_latex(rows, args.latex)

    return 0


if __name__ == "__main__":
    sys.exit(main())
