# openfhe-dpad

Standalone C++ implementations of the ModHE and DPad-HE approaches on top of OpenFHE, plus the benchmark suite that produced the numbers in the thesis.

## Paper coverage

Which benchmark and which plot answer which claim of the DPad paper. The paper states six research questions (RQ1-RQ6) and nine tables. Table 1 (HMult complexity) and Table 2 (asymptotic comparison) are theoretical, Tables 3 to 9 hold measurements. RQ4 and RQ5 are answered with a figure in the paper (Fig. 3, Fig. 4) rather than with a table; the list still names all six questions.

| Claim | Paper | Answer here |
|---|---|---|
| RQ1 | Table 3 (parameters, n = 2^13), Table 4 (HMult+Rescale time, relin key size, speedup) | `benchmark_hmult_rescale` |
| RQ2 | Table 5 (parameters, same multiplicative depth), Table 6 (CPU time), Table 7 (key size) | `benchmark_table5` |
| RQ2 (condition) | precision fairness condition of Sec. 5: ~33.9 bits at N = r x n = 2^15, ~33.4 at 2^16 | `benchmark_precision`, compared on the RNS-CKKS ring dimension |
| RQ3 | Table 8 (HMult+Rescale time on GPU) | not covered, no GPU backend on the test host |
| RQ4 | Fig. 3 (cumulative time over all multiplicative levels, with and without rank reduction) | `benchmark_circuit` in shape only: a different function (X x W instead of the paper's repeated squaring) at non-Table-5 parameters, and no with/without rank-reduction arm |
| RQ5 | Figure 4 (rank-hoisted rotation) | not covered, not implemented |
| RQ6 | Table 9 (MLWE-RLWE conversion) | not covered, outside the scope of this thesis |

Two claims of the paper outside the six questions are not covered. The paper proves a bound on the noise its key switching adds (Lemmas 3.1/3.2, "enhanced noise control" in the abstract); that bound is not reproduced here, and the harness reports OpenFHE's own error estimate instead. And the comparison grades the DPad-HE column of every table, so the RNS-CKKS and ModHE columns of Tables 6 and 7 are transcribed and measured but never checked cell by cell.

`benchmark_relin_breakdown` answers no research question of its own; it breaks the DPad relinearization into its rank-up and rank-down phases.

`scripts/compare_with_paper.py` is the evaluation step over these results: it reads the CSVs, lays every measured value next to the transcribed paper value, flags each cell `ok`/`OFF` against a 20% tolerance (denied runs as `denied`; the precision row uses an absolute 3-bit window instead). `--csv out.csv` dumps the comparison rows, `--latex out.tex` writes the same comparison as `booktabs` tables ready to `\input` in a `.tex` document.

## Test platform

```
OS       Parrot Security 7.4 (echo), x86_64
Kernel   7.1.13+parrot7-amd64
CPU      AMD Ryzen 7 5700U (16 threads) @ 4.37 GHz
RAM      30.73 GiB (~6.5 GiB idle, ~11.6 GiB peak during a ModHE run at r = 6)
Swap     disabled
```

## Requirements

- Linux on x86_64
- CMake and a C++17 compiler
- An OpenFHE checkout with the MODHE patches (the `MODHE` submodule)

The harness reads memory counters from `/proc/meminfo` and `/proc/self/statm`, so it is Linux-only.

## Build

Initialise the OpenFHE submodule, then configure and build from this folder:

```bash
git submodule update --init --recursive

mkdir -p build
cd build
cmake .. -DBUILD_UNITTESTS=OFF -DBUILD_BENCHMARKS=OFF
make -j$(nproc)
```

OpenFHE's own tests and benchmarks are disabled to avoid unrelated make errors.

CMake creates one executable per source file, so the target name is the file name without its extension.

## Run

```bash
./benchmark_hmult_rescale    # key size, runtime, RAM vs rank (Paper Table 3/4)
./benchmark_table5           # same-depth time and key size (Paper Table 5/6/7)
./benchmark_relin_breakdown  # standalone RankUp / RankDown timings
./benchmark_circuit          # multiplicative circuit, depth 6
./benchmark_precision        # precision vs rank (Paper Table 3 and fixed-L series)
./findings                   # the points the paper leaves open, demonstrated in code
```

The benchmarks write their results to `../results/` as CSV. The scripts in `scripts/` render the plots into `../plots/`. `run_all.sh` runs every benchmark and every plot script in sequence.

The SageMath 10.9 prototypes in `code/notebooks/` (01 ModHE baseline, 02 integrated DPad, 03 decoupled DPad) compute the same 0.4 x 0.6 product; they load the `.sage` files of the `MODHE` submodule by relative path, so they run with `code/` as the working directory.

`./findings` is the exception: it writes no CSV and it documents the points the paper leaves open, one block per point. `F1` the extra modulus of the `FLEXIBLEAUTOEXT` chain, `F2` the open digit count `mu` of the special modulus, `F3` the decoded precision as the noise floor of the decoder, `F4` the slot count inside the precision value, `F5` the ring dimension of the RNS-CKKS baseline, `F6` the no-op `Rescale` of the measured chain. Each block states the point and prints the numbers behind it.

## Measurement policy

Each test case is timed with two nested loops. The inner loop repeats the timed operation `--loops` times (default 10); the outer loop repeats that whole inner loop `--runs` times (default 3).

```
for run in 1..RUNS_PER_TEST:           # outer loop
    sum = 0
    for iter in 1..ITERATIONS_PER_RUN: # inner loop
        sum += time(operation)         # one timed measurement
    run_mean[run] = sum / ITERATIONS_PER_RUN
result = median(run_mean)              # what lands in the CSV
```

The two loops:

- **inner loop (`--loops`)** — repeats the timed operation and measures the block as a whole. Averages out timer overhead and OS jitter.
- **outer loop (`--runs`)** — repeats the block and takes the median over the block means, so a single slow block cannot move the result.

The inner loop is the length knob; `--loops` shortens a full run.

`benchmark_precision` has no inner loop: it takes one precision probe per repetition, so `--loops` sets its probe count directly (default 10) and `--runs` is ignored there.

```bash
./benchmark_hmult_rescale --loops 30     # longer pass, thirty iterations per measurement
./benchmark_hmult_rescale --help
```

`run_all.sh` forwards a single `--loops` value to all five benchmarks, so one setting covers the whole suite:

```bash
./run_all.sh 10 5      # 10 s between steps, 5 loops per benchmark
LOOPS=5 ./run_all.sh   # same, via environment variable
./run_all.sh --help
```

The last step of the script is `compare_with_paper.py`. It writes both its comparison CSV and its LaTeX tables into `results/`:

- `results/comparison_results.csv` — one row per compared quantity, with measured value, paper value and verdict
- `results/comparison_results.tex` — the same comparison as `booktabs` tables, ready to `\input` in a `.tex` document

### Runtime vs precision aggregate

Runtimes land in the CSV as the median over the outer loop. Precision is measured only by `benchmark_precision`, which reports the smallest precision over its probes (the largest error) instead of a median, so a smaller value means a worse run.

Each configuration is measured twice, once per execution mode:

- `Prec_*` — OpenFHE's own error estimate in bits (`Plaintext::GetLogPrecision()` under `EXEC_NOISE_ESTIMATION`). The paper's ~33.9 bits at N = 2^15 and ~33.4 at 2^16 (RQ2) come from a different quantity: the average of the negative log of the l2-norm between the expected and the decrypted message (paper Sec. 5), measured on an implementation whose decryption adds no noise. `Prec_*` is the number this library can put next to it, and it sits about one bit above.
- `L2_*` — `-log2(||expected - decrypted||_2)` over the packed slots (the difference of paper Sec. 5, aggregated over the vector instead of averaged per slot), measured under `EXEC_EVALUATION`. The decoder adds Gaussian noise whose magnitude follows the ring dimension and not the ciphertext, which floors this value near 20 bits at N = 2^15 (about 22 bits at N = 2^13, 21 at 2^14) and hides the real error. `benchmarks/findings.cpp` (F3) prints both numbers side by side.

Both passes pack a full plaintext, one slot per ring element of the context they run on (`N_rlwe / 2` for RLWE, `N / 2` for ModHE and DPad). The decoder estimates the noise as a standard deviation over the packed slots and normalizes it by twice the slot count (`StdDev()` in `ckkspackedencoding.cpp`), so a short plaintext measures something other than the ciphertext noise. `benchmarks/findings.cpp` (F4) prints the same chain over eight slots and over `N / 2` slots side by side: about 40 bits against 34.9 bits at `L = 19`, `N = 2^15`. The full plaintext reproduces both paper values within one bit (34.9 against 33.9 at `N = 2^15`, 34.4 against 33.4 at `N = 2^16`). What the condition has to deliver is that the three schemes are compared at matched precision, and there the numbers are tight: within one configuration they agree to about 0.2 bit (`precision_results.csv`: 35.37 / 35.37 / 35.38 at `L = 8`, 34.89 / 34.89 / 34.86 at `L = 19`).

The execution mode is a context parameter, so the estimation pass builds its own context per configuration and generates its own keys; that pass roughly doubles the runtime of this benchmark.

### Rescale in the measured chain

`benchmark_precision` and `benchmark_hmult_rescale` rescale after relinearization, as the paper's chain does. With the automatic scaling technique the multiplication already drops one tower, so the call leaves level and scaling factor unchanged; `benchmarks/findings.cpp` (F6) prints the state at every step.

### Key size

Key sizes are counted from the stored key objects: the number of ring elements times the number of RNS primes each element holds. A serialized key file is smaller, and a context here carries one more Q prime than the paper's `log2 q = 60 + 40 x L` counts (see `d` above), so the measured sizes sit about 1.15 to 1.35 times above the Table 4 and Table 7 values by construction. The measured times sit about 1.16 to 1.70 times above the Table 4 times. That offset is flagged by the comparison and not attributed to one cause: the paper's implementation is built on SEAL and measured single-threaded on an Intel Xeon Silver 4410Y with 128 GB of RAM, while this harness runs OpenFHE on the test host above, and this harness carries the extra Q prime.

## Output format

Each benchmark prints one block per test case and appends one row per test case to its CSV. A block lists the parameters and then one line per metric; the CSV header names the columns.

The two spellings for a missing value are:

- `denied` — the RAM guard refused to run the configuration
- `N/A` — the run happened but the value is not meaningful

In the CSV a refused run is written as `-1`. The plot scripts drop these values, so a configuration that was not measured never appears in a figure.

## Parameters

The main test set follows Paper Table 3 (`n = 2^13`). `L` is the multiplicative depth, `r` the base rank, `r_ext` the sloppy rank, and `mu` the large-digit count of the sloppy context.

```
r     :  2   3   4   5   6   7   8
L     :  8  13  19  25  30  35  41
r_ext :  3   4   5   7   8   9  10
mu    :  2   3   4   3   4   4   5
```

`mu` follows `ceil((L+1) / (K+1))`, where `K` is the 55-bit prime count in the paper's special modulus `log2 P_hat = 60 + 55 x K`. That notation is one 60-bit leading prime plus `K` 55-bit primes, so the sloppy context holds `K+1` primes and `mu` is the number of digits the `L+1` depth primes split into. For `r = 2..4` (`K = 4`) this gives `mu = r`; the higher ranks follow the same formula but no longer coincide with `r`. The paper fixes no value for `mu`, so this formula is a reconstruction: with `K` read off Table 3 it reproduces the paper's `log2 P_hat` sizes for all seven ranks and gives `mu = r` at `r = 2..4`, where the measured key ratio pins it against Table 4; for `r = 5..8` the same formula gives the digit count listed above.

`d` is the number of Q primes in a context: `L + 1` depth primes (`numPrimes = multDepth + 1`) plus the extra 20-bit modulus the default `FLEXIBLEAUTOEXT` scaling adds, so `d = L + 2`. The paper's `log2 q = 60 + 40 x L` counts the depth primes only.

A rank `r` module context holds `r` ring elements of dimension `N`, so its effective dimension is `N x r`. The plain RNS-CKKS baseline runs at `N_RLWE = N x r` (rounded up to a power of two) to reach the same dimension and therefore the same security level. That is why `N_RLWE` grows with the rank in the CSVs while `N` stays at 8192.

`benchmark_hmult_rescale`, `benchmark_precision` and `benchmark_circuit` share one case list format. Each `main()` ends with a block of `run_eval(...)` calls; add a line there with the same argument order:

```
run_eval("Test_Name", L, N, r, r_ext, mu, csv);
```

`benchmark_relin_breakdown` does not take cases this way: it loops over the rank `r = 2..8` itself and fixes `L`, `r_ext` and `mu` per rank in three arrays at the top of `main`.

## RAM guard

Every benchmark estimates the peak memory of a configuration before running it and skips it if the estimate does not fit:

```
run  <=>  estimated peak  <  available RAM  -  RAM_SAFETY_BUFFER_GB
```

`RAM_SAFETY_BUFFER_GB` (in `benchmark_common.hpp`) leaves headroom for the profiler thread, the OS and allocator fragmentation; lower it if a configuration you know fits is refused. `available RAM` is `MemAvailable` from `/proc/meminfo`, read once at startup.

## Plots

The scripts in `scripts/` render the plots into `../plots/`. Run them after a benchmark:

```bash
cd scripts
python3 generate_hmult_rescale_plots.py
python3 generate_table5_plots.py
python3 generate_relin_breakdown_plots.py
python3 generate_circuit_plots.py
python3 generate_precision_plots.py
```

Requires the packages in `scripts/requirements.txt` (numpy, matplotlib, pandas). `plot_common.py` holds the shared colours, labels and save helper.

Every figure speaks the same language:

- A series label is `<scheme>` or `<quantity>`, plus `(measured)`, `(estimated)`, `(Paper)` or `(OpenFHE estimate)` whenever a figure mixes sources.
- The colour identifies the scheme; the two phases of one scheme use its base colour and its light shade. Figures that compare operations instead of schemes use `ALT_COLORS`.
- Line style: solid is measured, dashed is a paper value, dotted is the RAM guard's analytic estimate.
- Every bar carries its value above it and no outline.
- A run the RAM guard refused leaves a gap and one grey line `not measured: <scheme> from r = <rank> (RAM guard)`.

### `generate_hmult_rescale_plots.py` (reads `hmult_rescale_results.csv`)

Covers Paper Table 4 (RQ1). `key_size_vs_rank` and `hmult_rescale_vs_rank` are the two Table-4 quantities; `speedup_vs_rank` is its Speedup column.

- `key_size_vs_rank.png` — relinearization key size over rank (Table 4, Size row). Solid lines are the measured key objects, dotted lines the RAM guard's analytic estimate.
- `hmult_rescale_vs_rank.png` — the full HMult + Relinearize + Rescale block over rank, normalized to rank 2 (Table 4, Time row).
- `relin_runtime_vs_rank.png` — the same data with the relinearization step alone, so the rank-up / rank-down advantage shows without the multiplication mixed in.
- `speedup_vs_rank.png` — the block's ModHE / DPad-HE runtime ratio (Table 4, Speedup row) next to the paper's own row over the same ranks. `1.0` means equal, above `1.0` means DPad is faster.
- `ram_vs_rank.png` — peak RAM over the same rank axis as the timing plots.

### `generate_table5_plots.py` (reads `table5_results.csv`)

Covers Paper Table 6 (Time, RQ2) and Table 7 (key size, RQ2).

Table 5 fixes `L` and varies `N`, so `mu = ceil((L+1)/(K+1))` no longer tracks `r`: with `K` from `log2 P_hat = 60 + 55 x K` (Set II: 6, Set III: 4, Set V: 13, Set VI: 9) it is 3, 4, 3, 5. Sets I and IV are plain RNS-CKKS and serve as the baseline column. The time ratio in `table5_results.csv` (`Ratio_DPad_vs_RNS_pct`) is DPad-HE over RNS-CKKS in percent, which is Table 7's convention; the paper's Table 6 prints the reciprocal, RNS-CKKS over DPad-HE, as a factor.

- `table5_time_vs_r.png` — HMult+Rescale time per set, DPad-HE against ModHE, with the RNS-CKKS baseline from Table 6 where available.
- `table5_key_size_vs_r.png` — relinearization key size per set (Table 7), DPad-HE against the Table-7 values.

### `generate_relin_breakdown_plots.py` (reads `relin_breakdown_results.csv`)

- `relin_components.png` — stacked bars of the relinearization pipeline: ModHE's single step against DPad's rank-down plus rank-up phases.
- `rankdown_comparison.png` — the rank-down phase alone: ModHE's native rank-down key against DPad's overflow mapping.

### `generate_circuit_plots.py` (reads `circuit_results.csv`)

- `circuit_runtime.png` — circuit runtime, normalized to the CKKS-RNS baseline (log scale).
- `circuit_ram.png` — peak RAM of the same circuit.
- `circuit_key_size.png` — measured evaluation key size.

The three real plots label the x-axis with the ring dimension `N` per task, because the tasks do not all use the same `N`.

### `generate_precision_plots.py` (reads `precision_results.csv`)

The y-value is the OpenFHE estimate of a configuration, worst case over its probes (see *Runtime vs precision aggregate*).

- `precision_vs_rank_paper.png` — worst-case precision over rank with `L` growing per Paper Table 3.
- `precision_vs_rank_fixedL.png` — worst-case precision over rank at fixed `L = 30`, which isolates the rank effect.

## Layout

```
benchmarks/   the five benchmark programs, findings.cpp and benchmark_common.hpp
scripts/      plot generation
results/      benchmark output (CSV)
plots/        rendered figures
src/          DPadHE.hpp / DPadHE.cpp, the DPad-HE implementation
```