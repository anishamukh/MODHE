#pragma once
#include "openfhe.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include "DPadHE.hpp"

using namespace lbcrypto;

// Measurement policy and the meaning of "denied"/"N/A" are documented in README.md.
inline int ITERATIONS_PER_RUN = 10;  // --loops : inner iterations per run
inline int RUNS_PER_TEST = 3;         // --runs  : runs, median is reported

// Set when --loops was passed, so the error benchmark (one probe per repetition,
// no inner loop) adopts the same count instead of its own default.
inline int LOOPS_OVERRIDE = 0;

// Read the loop-count flags from the command line. Returns 0 on success, 2 when
// --help was printed, 1 on a malformed flag.
inline int parse_loop_flags(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--loops" || arg == "--runs") {
            if (i + 1 >= argc) {
                std::cerr << "error: " << arg << " needs a value\n";
                return 1;
            }
            const int value = std::atoi(argv[++i]);
            if (value < 1) {
                std::cerr << "error: " << arg << " must be >= 1\n";
                return 1;
            }
            if (arg == "--runs") {
                RUNS_PER_TEST = value;
            } else {
                ITERATIONS_PER_RUN = value;
                LOOPS_OVERRIDE = value;
            }
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "options: --loops N (default 10)  --runs N (default 3)\n";
            return 2;
        } else {
            std::cerr << "error: unknown argument '" << arg << "'\n";
            return 1;
        }
    }
    return 0;
}

using Clock = std::chrono::high_resolution_clock;
inline double elapsed_ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

// =============================================================================
// Formatting helpers
// =============================================================================
// One fixed-decimal formatter for every terminal cell and every CSV field.
inline std::string fmt(double value, int precision = 2) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(precision) << value;
    return os.str();
}

// Renders the negative CSV sentinels as "N/A"; real values go through fmt().
inline std::string fmt_or_na(double value, int precision = 2) {
    return value < 0.0 ? std::string("N/A") : fmt(value, precision);
}

// Terminal cell for one algorithm: "denied" if the RAM guard refused it,
// otherwise the formatted value.
inline std::string cell(bool ran, double value, int precision = 2) {
    return ran ? fmt(value, precision) : std::string("denied");
}

// CSV counterpart of cell(): the measured value scaled into the column's unit,
// or the -1 sentinel if the RAM guard refused the run. The scale applies only
// to a real measurement, so it can never distort the sentinel.
constexpr double csv_field(bool ran, double value, double scale = 1.0) {
    return ran ? value * scale : -1.0;
}

// =============================================================================
// Terminal report layout
// =============================================================================
// Shared by all five benchmarks so the reports read the same way: a name line,
// a parameter line and one row per metric, algorithms ordered RLWE, ModHE, DPad.
inline constexpr int REPORT_INDENT = 4;
inline constexpr int REPORT_LABEL_WIDTH = 22;
inline constexpr int REPORT_VALUE_WIDTH = 11;

inline void report_header(const std::string& name, const std::string& params) {
    std::cout << "\n" << name << "\n"
              << std::string(REPORT_INDENT, ' ') << params << "\n";
}

// One metric row: label on the left, then one "ALGO value" cell per algorithm.
inline void report_row(const std::string& label, const std::string& rlwe,
                       const std::string& modhe, const std::string& dpad) {
    std::cout << std::string(REPORT_INDENT, ' ') << std::left << std::setw(REPORT_LABEL_WIDTH)
              << label << ": "
              << "RLWE " << std::left << std::setw(REPORT_VALUE_WIDTH) << rlwe << "   "
              << "ModHE " << std::left << std::setw(REPORT_VALUE_WIDTH) << modhe << "   "
              << "DPad " << std::left << std::setw(REPORT_VALUE_WIDTH) << dpad << "\n";
}

// A row that is not one value per algorithm, e.g. a ratio or a note.
inline void report_note(const std::string& label, const std::string& text) {
    std::cout << std::string(REPORT_INDENT, ' ') << std::left << std::setw(REPORT_LABEL_WIDTH)
              << label << ": " << text << "\n";
}

// Precision metric per the paper (Sec. 5, RQ2): the negative base-2 logarithm of
// the ℓ2-norm of the error over the packed slots. Larger is more accurate. A zero
// norm is reported as "INF".
inline std::string precision_metric(const std::vector<double>& expected,
                                    const std::vector<double>& actual) {
    const size_t n = std::min(expected.size(), actual.size());
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        const double diff = expected[i] - actual[i];
        sum += diff * diff;
    }
    const double norm = std::sqrt(sum);
    if (norm <= 0.0) return std::string("INF");
    return fmt(-std::log2(norm), 2);
}

// Decrypt and return up to `n` packed slots of a result.
inline std::vector<double> decrypted_slots(const Plaintext& res, size_t n) {
    std::vector<double> v = res->GetRealPackedValue();
    v.resize(n);
    return v;
}

// =============================================================================
// Key-size measurement
// =============================================================================
// Key sizes are counted structurally, tower by tower, from the key objects:
// every tower contributes ring_dimension * ceil(modulus_bits / 8) bytes of
// coefficient data. Serialization is not used because DCRTModule evaluation keys
// are not cereal-registered. A negative return means the count failed.
inline constexpr double BYTES_PER_GB = 1024.0 * 1024.0 * 1024.0;

inline double structural_bytes(const DCRTPoly& poly) {
    double bytes = 0.0;
    const usint towers = poly.GetNumOfElements();
    for (usint t = 0; t < towers; ++t) {
        const auto& tower = poly.GetElementAtIndex(t);
        const usint n = tower.GetLength();
        const usint bits = tower.GetModulus().GetMSB();
        bytes += (double)n * std::ceil((double)bits / 8.0);
    }
    return bytes;
}

inline double structural_bytes(const DCRTModule& mod) {
    double bytes = 0.0;
    const usint count = mod.GetModuleRows() * mod.GetModuleCols();
    for (usint i = 0; i < count; ++i)
        bytes += structural_bytes(mod.GetDCRTPolyAt(i));
    return bytes;
}

// One evaluation key: the A and B vectors together carry the key material.
// Any accessor that is unsupported for the key type throws, which is caught here
// and reported as a failure rather than a wrong size.
template <typename Element>
inline double structural_key_bytes(const EvalKey<Element>& key) {
    try {
        double bytes = 0.0;
        for (const auto& e : key->GetAVector()) bytes += structural_bytes(e);
        for (const auto& e : key->GetBVector()) bytes += structural_bytes(e);
        return bytes;
    } catch (...) {
        return -1.0;
    }
}

// Sum of every EvalMult key registered for a context, in GB.
template <typename Element>
inline double context_key_gb() {
    try {
        double bytes = 0.0;
        for (const auto& entry : CryptoContextImpl<Element>::GetAllEvalMultKeys())
            for (const auto& key : entry.second)
                bytes += structural_key_bytes(key);
        return bytes / BYTES_PER_GB;
    } catch (...) {
        return -1.0;
    }
}

// One EvalKey, in GB.
template <typename Element>
inline double eval_key_gb(const EvalKey<Element>& key) {
    const double bytes = structural_key_bytes(key);
    return bytes < 0.0 ? -1.0 : bytes / BYTES_PER_GB;
}

// Sum of several measured key sizes; -1 if any single one failed, so a partial
// failure never reports a too-small total.
inline double sum_key_gb(std::initializer_list<double> parts) {
    double total = 0.0;
    for (double p : parts) {
        if (p < 0.0) return -1.0;
        total += p;
    }
    return total;
}

// Median of a set of measurements.
inline double median(std::vector<double> values) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const size_t n = values.size();
    return (n % 2) ? values[n / 2] : 0.5 * (values[n / 2 - 1] + values[n / 2]);
}

// Smallest value in a set of measurements.
inline double min_value(const std::vector<double>& values) {
    return *std::min_element(values.begin(), values.end());
}

// =============================================================================
// Context teardown
// =============================================================================
// Called after every algorithm block so the next algorithm starts from a clean
// heap.
template <typename Element>
inline void release_contexts() {
    CryptoContextImpl<Element>::ClearEvalMultKeys();
    CryptoContextImpl<Element>::ClearEvalSumKeys();
    CryptoContextImpl<Element>::ClearEvalAutomorphismKeys();
    CryptoContextFactory<Element>::ReleaseAllContexts();
    malloc_trim(0);
}

// =============================================================================
// RAM guard
// =============================================================================
// Runs a configuration only if its estimated peak stays below (available RAM -
// buffer). The buffer keeps headroom for the profiler thread, the OS and
// allocator fragmentation spikes.
inline constexpr double RAM_SAFETY_BUFFER_GB = 4.0;

inline double get_available_ram_gb() {
    std::ifstream meminfo("/proc/meminfo");
    std::string line;
    while (std::getline(meminfo, line)) {
        if (line.rfind("MemAvailable:", 0) == 0) {
            long long kb = 0;
            if (sscanf(line.c_str(), "MemAvailable: %lld kB", &kb) == 1)
                return (double)kb / (1024.0 * 1024.0);
        }
    }
    // No MemAvailable line: fall back to the available physical page count.
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0)
        return ((double)pages * (double)page_size) / (1024.0 * 1024.0 * 1024.0);
    // Still unknown: deny everything instead of guessing a number.
    std::cerr << "[ram-guard] cannot read available RAM; denying all runs." << std::endl;
    return 0.0;
}

inline double g_initial_ram_gb = 0.0;

struct RamGuard {
    bool run_rlwe;
    bool run_modhe;
    bool run_dpad;
    double rlwe_key_gb;
    double modhe_key_gb;
    double dpad_key_gb;
};

// The guard's analytic key-size figures, kept separate from the measured sizes.
inline RamGuard calculate_ram_guard(int L, int N, int N_rlwe, int r, int r_ext, int mu, double initial_ram_gb) {
    int Q_towers = L + 2;
    int d = Q_towers;

    double poly_size_gb = (double)(8 * N * d) / (1024.0 * 1024.0 * 1024.0);
    double rlwe_poly_size_gb = (double)(8 * N_rlwe * d) / (1024.0 * 1024.0 * 1024.0);

    double modhe_key_gb = ((r * (r + 1)) / 2.0) * (r + 1) * d * poly_size_gb;
    double dpad_sloppy_key_gb = ((r * (r + 1)) / 2.0) * (r_ext + 1) * mu * poly_size_gb;
    double dpad_strict_key_gb = (r_ext - r) * (r + 1) * d * poly_size_gb;
    double dpad_key_gb = dpad_sloppy_key_gb + dpad_strict_key_gb;
    double rlwe_key_gb = 2.0 * d * rlwe_poly_size_gb;

    double rlwe_est_gb = rlwe_key_gb + 3.0;

    double extended_poly_gb = (double)(8 * N * (d + 1)) / (1024.0 * 1024.0 * 1024.0);
    int r_new = (r * (r - 1)) / 2;
    if (r_new < r) r_new = r;
    double modhe_raw_matrices_gb = (d * r * r_new + d * r) * extended_poly_gb;
    double modhe_est_gb = modhe_key_gb + modhe_raw_matrices_gb * 1.5;

    double dpad_sloppy_raw_gb = (mu * r_ext * r_new + mu * r_ext) * extended_poly_gb;
    int r_overflow = r_ext - r;
    double dpad_strict_raw_gb = (d * r * r_overflow + d * r) * extended_poly_gb;
    double dpad_raw_matrices_gb = std::max(dpad_sloppy_raw_gb, dpad_strict_raw_gb);
    double dpad_est_gb = dpad_key_gb + dpad_raw_matrices_gb * 1.5;

    RamGuard guard;
    guard.rlwe_key_gb = rlwe_key_gb;
    guard.modhe_key_gb = modhe_key_gb;
    guard.dpad_key_gb = dpad_key_gb;
    guard.run_rlwe = (rlwe_est_gb < (initial_ram_gb - RAM_SAFETY_BUFFER_GB));
    guard.run_modhe = (modhe_est_gb < (initial_ram_gb - RAM_SAFETY_BUFFER_GB));
    guard.run_dpad = (dpad_est_gb < (initial_ram_gb - RAM_SAFETY_BUFFER_GB));
    return guard;
}

struct DPadContext {
    CryptoContext<DCRTModule> cc_P_hat;
    CryptoContext<DCRTModule> cc_P;
    KeyPair<DCRTModule> keys;
};

struct RLWEContext {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
};

// The execution mode is a context parameter: EXEC_NOISE_ESTIMATION makes Decrypt
// report OpenFHE's error estimate (Plaintext::GetLogPrecision()) instead of the
// decoded values.
RLWEContext setup_rlwe_context(int L, int N_rlwe, int d, ExecutionMode mode = EXEC_EVALUATION) {
    RLWEContext ctx;
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(L);
    params.SetScalingModSize(40);
    params.SetFirstModSize(60);
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(N_rlwe);
    params.SetNumLargeDigits(d);
    params.SetExecutionMode(mode);

    ctx.cc = GenCryptoContext(params);
    ctx.cc->Enable(PKE); ctx.cc->Enable(KEYSWITCH); ctx.cc->Enable(LEVELEDSHE);
    ctx.keys = ctx.cc->KeyGen();
    ctx.cc->EvalMultKeyGen(ctx.keys.secretKey);
    return ctx;
}

struct ModHEContext {
    CryptoContext<DCRTModule> cc;
    KeyPair<DCRTModule> keys;
};

ModHEContext setup_modhe_context(int L, int N, int r, int d, ExecutionMode mode = EXEC_EVALUATION) {
    ModHEContext ctx;
    CCParams<CryptoContextCKKSMod> params;
    params.SetMultiplicativeDepth(L);
    params.SetScalingModSize(40);
    params.SetFirstModSize(60);
    params.SetModuleRank(r);
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(N);
    params.SetNumLargeDigits(d);
    params.SetExecutionMode(mode);

    ctx.cc = GenCryptoContext(params);
    ctx.cc->Enable(PKE); ctx.cc->Enable(KEYSWITCH); ctx.cc->Enable(LEVELEDSHE);
    ctx.keys = ctx.cc->KeyGen();
    ctx.cc->EvalMultModKeyGen(ctx.keys.secretKey);
    return ctx;
}

// =============================================================================
// DPad context: strict (P) and sloppy (P_hat)
// =============================================================================
// Two CKKS contexts at two module ranks: cc_P (rank r, numDigitsStrict) is where
// a fresh ciphertext lives; cc_P_hat (rank r_ext > r, numDigitsSloppy = mu) is
// the rank the rank-up step expands into. Keys are generated once against the
// strict context and reused by both.
DPadContext setup_dpad_context(int L, int N, int r, int r_ext, int numDigitsStrict, int numDigitsSloppy,
                               ExecutionMode mode = EXEC_EVALUATION) {
    DPadContext ctx;

    CCParams<CryptoContextCKKSMod> params_strict;
    params_strict.SetMultiplicativeDepth(L);
    params_strict.SetScalingModSize(40);
    params_strict.SetFirstModSize(60);
    params_strict.SetModuleRank(r);
    params_strict.SetSecurityLevel(HEStd_NotSet);
    params_strict.SetRingDim(N);
    params_strict.SetNumLargeDigits(numDigitsStrict);
    params_strict.SetExecutionMode(mode);
    ctx.cc_P = GenCryptoContext(params_strict);
    ctx.cc_P->Enable(PKE); ctx.cc_P->Enable(KEYSWITCH); ctx.cc_P->Enable(LEVELEDSHE);

    CCParams<CryptoContextCKKSMod> params_sloppy;
    params_sloppy.SetMultiplicativeDepth(L);
    params_sloppy.SetScalingModSize(40);
    params_sloppy.SetFirstModSize(60);
    params_sloppy.SetModuleRank(r_ext);
    params_sloppy.SetSecurityLevel(HEStd_NotSet);
    params_sloppy.SetRingDim(N);
    params_sloppy.SetNumLargeDigits(numDigitsSloppy);
    params_sloppy.SetExecutionMode(mode);
    ctx.cc_P_hat = GenCryptoContext(params_sloppy);
    ctx.cc_P_hat->Enable(PKE); ctx.cc_P_hat->Enable(KEYSWITCH); ctx.cc_P_hat->Enable(LEVELEDSHE);

    ctx.keys = ctx.cc_P->KeyGen();

    return ctx;
}

class MemProfiler {
    std::atomic<bool> running{false};
    std::atomic<long long> peak_rss{0};
    std::thread profiler_thread;
public:
    void start() {
        peak_rss = 0;
        running = true;
        profiler_thread = std::thread([this]() {
            long page_size = sysconf(_SC_PAGESIZE);
            while (running) {
                std::ifstream statm("/proc/self/statm");
                long long size = 0, resident = 0;
                if (statm >> size >> resident) {
                    long long current_rss = resident * page_size;
                    long long current_peak = peak_rss.load();
                    while (current_rss > current_peak && !peak_rss.compare_exchange_weak(current_peak, current_rss)) {}
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });
    }
    double stop_and_get_gb() {
        running = false;
        if (profiler_thread.joinable()) profiler_thread.join();
        return (double)peak_rss.load() / (1024.0 * 1024.0 * 1024.0);
    }
    static double get_current_rss_gb() {
        std::ifstream statm("/proc/self/statm");
        long long size = 0, resident = 0;
        if (statm >> size >> resident) {
            return (double)(resident * sysconf(_SC_PAGESIZE)) / (1024.0 * 1024.0 * 1024.0);
        }
        return 0.0;
    }
};

// Wrappers matching the short call sites used in the benchmarks.
inline lbcrypto::dpad::DPadKeys generate_dpad_keys(DPadContext& ctx, int r, int r_ext) {
    return lbcrypto::dpad::generate_dpad_keys(ctx.cc_P_hat, ctx.cc_P, ctx.keys.secretKey, r, r_ext);
}

inline lbcrypto::Ciphertext<lbcrypto::DCRTModule> DPad_Relin(DPadContext& ctx, lbcrypto::Ciphertext<lbcrypto::DCRTModule>& ct_tensor, const lbcrypto::dpad::DPadKeys& dpad_keys, int r, int r_ext) {
    return lbcrypto::dpad::DPad_Relin(ctx.cc_P_hat, ctx.cc_P, ct_tensor, dpad_keys, r, r_ext);
}

// Measured size of the three DPad keys (cross-relinearization hadamard + lower,
// rank-down key), summed. -1 if any of them could not be counted.
inline double dpad_keys_gb(const lbcrypto::dpad::DPadKeys& keys) {
    return sum_key_gb({ eval_key_gb(keys.crlk_hadamard),
                        eval_key_gb(keys.crlk_lower),
                        eval_key_gb(keys.rdk) });
}
