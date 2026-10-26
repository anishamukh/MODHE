#!/usr/bin/env bash
#
# Runs the benchmark executables, then the plot scripts, then the paper
# comparison, pausing between every step so the machine cools down between runs.
#
#   ./run_all.sh              # 10 s between steps, default loops per measurement
#   ./run_all.sh 30           # 30 s between steps
#   ./run_all.sh 10 5         # 10 s between steps, 5 loops per benchmark
#   LOOPS=5 ./run_all.sh      # same loop count via environment variable
#   DELAY_S=5 ./run_all.sh    # same delay via environment variable
#   ./run_all.sh --help
#
# The loop count is forwarded to every benchmark as --loops, so one value covers
# the whole suite. Assumes the project is already built (build/ exists): the
# benchmarks are read from build/ and write into results/, the plot scripts read
# results/ and write into plots/. The last step runs compare_with_paper.py and
# writes both its CSV and its LaTeX tables into results/.

set -euo pipefail

usage() {
    cat <<'EOF'
usage: run_all.sh [DELAY_S [LOOPS]]

  DELAY_S   seconds to pause between steps (default 10, or $DELAY_S)
  LOOPS     --loops value forwarded to every benchmark (default: benchmark's own)

  -h, --help   show this help
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
esac

DELAY_S="${1:-${DELAY_S:-10}}"
LOOPS="${2:-${LOOPS:-}}"
BIN_DIR="${BIN_DIR:-build}"
PYTHON="${PYTHON:-python3}"

# Empty means "use the benchmark's built-in default"; otherwise forward it.
if [[ -n "$LOOPS" ]]; then
    BENCH_FLAGS=(--loops "$LOOPS")
else
    BENCH_FLAGS=()
fi

BENCHMARKS=(
    benchmark_hmult_rescale
    benchmark_table5
    benchmark_relin_breakdown
    benchmark_precision
    benchmark_circuit
)

PLOTS=(
    generate_hmult_rescale_plots.py
    generate_table5_plots.py
    generate_relin_breakdown_plots.py
    generate_precision_plots.py
    generate_circuit_plots.py
)

# Final step: cross-check the measured CSVs against the published paper tables.
COMPARE_CSV="results/comparison_results.csv"
COMPARE_TEX="results/comparison_results.tex"

cd "$(dirname "$0")"

# Fail early, before the first long run, if something was not built.
for b in "${BENCHMARKS[@]}"; do
    if [[ ! -x "$BIN_DIR/$b" ]]; then
        echo "error: $BIN_DIR/$b not found or not executable — build first" >&2
        exit 1
    fi
done

total=$(( ${#BENCHMARKS[@]} + ${#PLOTS[@]} + 1 ))
step=0

for b in "${BENCHMARKS[@]}"; do
    step=$(( step + 1 ))
    echo
    echo "=== [$step/$total] $b ===${LOOPS:+ (--loops $LOOPS)}"
    ( cd "$BIN_DIR" && exec "./$b" "${BENCH_FLAGS[@]}" )
    if (( step < total )); then
        echo "--- waiting ${DELAY_S}s ---"
        sleep "$DELAY_S"
    fi
done

for p in "${PLOTS[@]}"; do
    step=$(( step + 1 ))
    echo
    echo "=== [$step/$total] $p ==="
    ( cd scripts && exec "$PYTHON" "$p" )
done

# Compare the measured results against the paper; both outputs land in results/.
step=$(( step + 1 ))
echo
echo "=== [$step/$total] compare_with_paper.py ==="
mkdir -p results
( cd scripts && exec "$PYTHON" compare_with_paper.py \
    --csv "../$COMPARE_CSV" --latex "../$COMPARE_TEX" )

echo
echo "done — results in results/, plots in plots/"
