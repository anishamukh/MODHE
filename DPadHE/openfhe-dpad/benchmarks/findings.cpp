#include "benchmark_common.hpp"

// Findings: what the paper leaves open, and how each point was settled.
//
// The DPad paper fixes its parameter sets and reports its measurements, but
// several pieces of the setup appear only in the implementation, not in the
// text. Each block below states one of those points, runs the code that settles
// it and prints the numbers behind it. Everything here builds parameter-sized
// contexts or runs a single chain, so the program is safe on a laptop.
//
//   F1  the modulus chain carries L + 2 primes, the paper's log2 q counts L + 1
//   F2  the special modulus log2 P_hat = 60 + 55 x K leaves the digit count open
//   F3  the decoded l2 precision is the noise floor of the decoder
//   F4  the precision value depends on the slot count of the plaintext
//   F5  the RNS-CKKS baseline needs N_RLWE = N x r, not N
//   F6  the explicit Rescale under FLEXIBLEAUTOEXT changes no level and no scale
static constexpr size_t BASE_SLOTS = 8;  // distinct values, repeated over the slots

// ---------------------------------------------------------------------------
// Small helpers, so this file stays readable on its own.
// ---------------------------------------------------------------------------
std::vector<double> first_n(const std::vector<double>& v, size_t n) {
    return std::vector<double>(v.begin(), v.begin() + std::min(n, v.size()));
}

// Level, scaling factor, noise scale degree and modulus towers of a ciphertext.
std::string ct_state(const Ciphertext<DCRTPoly>& ct) {
    const DCRTPoly& c0 = ct->GetElements()[0];
    const usint towers = c0.GetNumOfElements();
    int min_bits = 1 << 30, max_bits = 0;
    for (usint t = 0; t < towers; ++t) {
        const int bits = (int)c0.GetElementAtIndex(t).GetModulus().GetMSB();
        min_bits = std::min(min_bits, bits);
        max_bits = std::max(max_bits, bits);
    }
    std::ostringstream os;
    os << "level " << ct->GetLevel() << ", log2 sf " << fmt(std::log2(ct->GetScalingFactor()), 2)
       << ", deg " << ct->GetNoiseScaleDeg() << ", " << towers << " towers of "
       << min_bits << ".." << max_bits << " bit";
    return os.str();
}

void fill_pair(std::vector<double>& x1, std::vector<double>& x2, size_t slots) {
    x1.resize(slots);
    x2.resize(slots);
    for (size_t i = 0; i < slots; ++i) {
        x1[i] = 0.1 * (double)((i % BASE_SLOTS) + 1);
        x2[i] = 0.2 * (double)((i % BASE_SLOTS) + 1);
    }
}

// ---------------------------------------------------------------------------
// F1: the modulus chain carries L + 2 primes.
// ---------------------------------------------------------------------------
// The paper sizes the modulus chain as log2 q = 60 + 40 x L, i.e. one 60-bit
// prime plus L 40-bit primes. OpenFHE's default FLEXIBLEAUTOEXT scaling appends
// one more modulus, so a context built with multDepth = L holds L + 2 Q primes
// and every ciphertext starts one tower deeper than the paper's chain. The tower
// count of a fresh ciphertext makes that visible; the RAM guard in
// benchmark_common.hpp uses the same figure (Q_towers = L + 2).
void finding_modulus_chain() {
    report_header("F1  modulus chain", "fresh ciphertext, N = 8192");

    for (const int L : {8, 13, 19}) {
        const RamGuard guard = calculate_ram_guard(L, 8192, 8192, 1, 1, 1, g_initial_ram_gb);
        if (!guard.run_rlwe) {
            report_note("L = " + std::to_string(L), "denied by the RAM guard");
            continue;
        }
        std::vector<double> x1, x2;
        fill_pair(x1, x2, BASE_SLOTS);

        const auto ctx = setup_rlwe_context(L, 8192, L + 2);
        const auto ct = ctx.cc->Encrypt(ctx.keys.publicKey, ctx.cc->MakeCKKSPackedPlaintext(x1));

        const DCRTPoly& c0 = ct->GetElements()[0];
        const usint towers = c0.GetNumOfElements();
        int min_bits = 1 << 30, max_bits = 0;
        for (usint t = 0; t < towers; ++t) {
            const int bits = (int)c0.GetElementAtIndex(t).GetModulus().GetMSB();
            min_bits = std::min(min_bits, bits);
            max_bits = std::max(max_bits, bits);
        }

        std::ostringstream out;
        out << towers << " towers of " << min_bits << ".." << max_bits << " bit";
        out << "   (paper: L + 1 = " << L + 1 << " towers, log2 q = 60 + 40 x L = " << 60 + 40 * L << ")";
        report_note("L = " + std::to_string(L), out.str());
        release_contexts<DCRTPoly>();
    }
}

// ---------------------------------------------------------------------------
// F2: the special modulus leaves the digit count open.
// ---------------------------------------------------------------------------
// Paper Table 3 writes the special modulus of the KeySwitch_mu step as
// log2 P_hat = 60 + 55 x K with K = 4 at the r = 2..4 test points, that is one
// 60-bit and four 55-bit primes, 280 bits in total. The digit count mu is left
// to the implementation. OpenFHE sizes the P basis from mu = numLargeDigits and
// gives its primes the size of the largest Q digit, so the basis it builds is
// mu-dependent and slightly larger than the paper's 280 bits. That is the larger
// part of the offset the measured key sizes show against Table 4.
//
// The eval-mult key lives in the extended basis Q x P, so the towers past the
// Q chain are the P towers.
void finding_special_modulus() {
    report_header("F2  special modulus", "RLWE eval-mult key, L = 19, N = 8192, paper log2 P_hat = 280");

    const int L = 19, N = 8192;
    const usint q_towers = (usint)(L + 2);

    for (int mu = 1; mu <= 6; ++mu) {
        const RamGuard guard = calculate_ram_guard(L, N, N, 1, 1, mu, g_initial_ram_gb);
        if (!guard.run_rlwe) {
            report_note("mu = " + std::to_string(mu), "denied by the RAM guard");
            continue;
        }
        try {
            const auto ctx = setup_rlwe_context(L, N, mu);
            const auto& all_keys = CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys();
            if (all_keys.empty() || all_keys.begin()->second.empty()) {
                report_note("mu = " + std::to_string(mu), "no eval-mult key registered");
                release_contexts<DCRTPoly>();
                continue;
            }
            const EvalKey<DCRTPoly> key = all_keys.begin()->second.front();
            const DCRTPoly& poly = key->GetAVector().front();

            const usint towers = poly.GetNumOfElements();
            const usint p_towers = towers > q_towers ? towers - q_towers : 0;
            int p_bits = 0, p_min = 1 << 30, p_max = 0;
            for (usint t = q_towers; t < towers; ++t) {
                const int bits = (int)poly.GetElementAtIndex(t).GetModulus().GetMSB();
                p_bits += bits;
                p_min = std::min(p_min, bits);
                p_max = std::max(p_max, bits);
            }

            std::ostringstream out;
            out << "P " << p_towers << " towers";
            if (p_towers) out << " of " << p_min << ".." << p_max << " bit";
            out << ", log2 P_hat = " << p_bits << "   (paper 280)";
            out << ", key A-vector " << fmt(structural_bytes(poly) / (1024.0 * 1024.0), 2) << " MB";
            report_note("mu = " + std::to_string(mu), out.str());
        } catch (const std::exception& e) {
            report_note("mu = " + std::to_string(mu), std::string("rejected by OpenFHE: ") + e.what());
        }
        release_contexts<DCRTPoly>();
    }
}

// ---------------------------------------------------------------------------
// F3, F4, F6: one chain, printed twice.
// ---------------------------------------------------------------------------
// F3  The paper states its precision as the decoded l2 error. The decoder adds
//     Gaussian noise of its own, so that value is a floor set by the ring
//     dimension rather than by the chain. OpenFHE's estimate under
//     EXEC_NOISE_ESTIMATION is the value that compares to the paper's ~33.9 bits
//     at N = 2^15.
// F4  Both conventions depend on the slot count of the plaintext, so a probe on
//     a short vector reads a different value than the benchmark's full plaintext.
// F6  With FLEXIBLEAUTOEXT the multiplication already drops one tower, so the
//     explicit Rescale of the paper's chain leaves level and scale unchanged.
void finding_precision_chain() {
    report_header("F3/F4/F6  precision chain", "HMult + Relinearize + Rescale, L = 19, N = 32768");

    const int L = 19, N = 32768;
    const size_t full_slots = (size_t)N / 2;
    const RamGuard guard = calculate_ram_guard(L, N, N, 1, 1, 1, g_initial_ram_gb);
    if (!guard.run_rlwe) {
        report_note("chain", "denied by the RAM guard");
        return;
    }

    std::vector<double> x1, x2;
    fill_pair(x1, x2, full_slots);
    std::vector<double> expected(full_slots);
    for (size_t i = 0; i < full_slots; ++i) expected[i] = x1[i] * x2[i];

    // Pass 1, EXEC_EVALUATION: the decoded values, so the error is measurable.
    try {
        const auto ctx = setup_rlwe_context(L, N, L + 2);
        const auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey, ctx.cc->MakeCKKSPackedPlaintext(x1));
        const auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey, ctx.cc->MakeCKKSPackedPlaintext(x2));

        report_note("F6  fresh", ct_state(ct1));
        const auto tensor = ctx.cc->EvalMultNoRelin(ct1, ct2);
        const auto relin = ctx.cc->Relinearize(tensor);
        report_note("F6  after EvalMult", ct_state(tensor));
        report_note("F6  after Relin", ct_state(relin));
        const auto rescaled = ctx.cc->Rescale(relin);
        report_note("F6  after Rescale", ct_state(rescaled));

        Plaintext res;
        ctx.cc->Decrypt(ctx.keys.secretKey, rescaled, &res);
        const std::vector<double> got = res->GetRealPackedValue();
        report_note("F3  decoded l2", precision_metric(expected, got) + " bits over "
                                     + std::to_string(got.size()) + " slots");
        report_note("F3  decode reports", fmt(res->GetLogPrecision(), 2)
                                        + " bits for the same ciphertext");
        report_note("F4  decoded l2, 8 slots", precision_metric(first_n(expected, BASE_SLOTS),
                                                               first_n(got, BASE_SLOTS)) + " bits");
    } catch (const std::exception& e) {
        report_note("evaluation pass failed", e.what());
    }
    release_contexts<DCRTPoly>();

    // Pass 2, EXEC_NOISE_ESTIMATION: OpenFHE's own estimate, once on the full
    // plaintext and once on eight slots.
    try {
        const auto ctx = setup_rlwe_context(L, N, L + 2, EXEC_NOISE_ESTIMATION);
        for (const size_t slots : {full_slots, BASE_SLOTS}) {
            const auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey,
                                             ctx.cc->MakeCKKSPackedPlaintext(first_n(x1, slots)));
            const auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey,
                                             ctx.cc->MakeCKKSPackedPlaintext(first_n(x2, slots)));
            const auto ct = ctx.cc->Rescale(ctx.cc->Relinearize(ctx.cc->EvalMultNoRelin(ct1, ct2)));

            Plaintext res;
            ctx.cc->Decrypt(ctx.keys.secretKey, ct, &res);
            std::ostringstream out;
            out << "estimate " << fmt(res->GetLogPrecision(), 2) << " bits (log2 error "
                << fmt(res->GetLogError(), 2) << ")";
            report_note("F3/F4  estimate, " + std::to_string(slots) + " slots", out.str());
        }
        report_note("paper", "~33.9 bits at N = 2^15, the RQ2 condition of Sec. 5");
    } catch (const std::exception& e) {
        report_note("estimation pass failed", e.what());
    }
    release_contexts<DCRTPoly>();
}

// ---------------------------------------------------------------------------
// F5: the baseline ring dimension.
// ---------------------------------------------------------------------------
// The paper compares against a plain RNS-CKKS implementation but does not say
// which ring dimension it runs at. A rank-r module context carries r ring
// elements of degree N in its key material, while the module ciphertext itself
// stays at one element, so the fair RNS-CKKS baseline is N_RLWE = N x r. The
// demo counts ring elements on both sides.
void finding_baseline_dimension() {
    report_header("F5  baseline dimension", "one context per line, L = 19, N = 8192, r = 4");

    const int L = 19, N = 8192, r = 4;
    std::vector<double> x1, x2;
    fill_pair(x1, x2, BASE_SLOTS);

    // The RNS-CKKS baseline at the module ring dimension and at the matched one.
    for (const int dim : {N, N * r}) {
        try {
            const auto ctx = setup_rlwe_context(L, dim, L + 2);
            const auto ct = ctx.cc->Encrypt(ctx.keys.publicKey, ctx.cc->MakeCKKSPackedPlaintext(x1));
            const usint elements = ct->GetElements().size();
            const usint degree = ct->GetElements()[0].GetElementAtIndex(0).GetLength();

            std::ostringstream out;
            out << elements << " components x 1 ring element of " << degree << " = "
                << degree << " coefficients per component";
            report_note("RNS-CKKS, N = " + std::to_string(dim), out.str());
        } catch (const std::exception& e) {
            report_note("RNS-CKKS at N = " + std::to_string(dim), e.what());
        }
        release_contexts<DCRTPoly>();
    }

    // The module side: the rank sits in the evaluation keys, not in the
    // ciphertext, which stays at a single ring element.
    try {
        const auto ctx = setup_modhe_context(L, N, r, L + 2);
        const auto ct = ctx.cc->Encrypt(ctx.keys.publicKey, ctx.cc->MakeCKKSPackedPlaintext(x1));
        const DCRTModule& c0 = ct->GetElements()[0];
        report_note("ModHE ciphertext", std::to_string(c0.GetModuleRows()) + " x "
                                        + std::to_string(c0.GetModuleCols()) + " module of degree "
                                        + std::to_string(c0.GetDCRTPolyAt(0).GetElementAtIndex(0).GetLength()));

        const auto& all_keys = CryptoContextImpl<DCRTModule>::GetAllEvalMultKeys();
        if (!all_keys.empty() && !all_keys.begin()->second.empty()) {
            const DCRTModule& km = all_keys.begin()->second.front()->GetAVector().front();
            const usint rows = km.GetModuleRows(), cols = km.GetModuleCols();
            const usint degree = km.GetDCRTPolyAt(0).GetElementAtIndex(0).GetLength();
            std::ostringstream out;
            out << rows << " x " << cols << " module entries, " << rows << " ring elements of "
                << degree << " = " << rows * degree << " coefficients per row";
            report_note("ModHE key, rank " + std::to_string(r), out.str());
        }
        report_note("matching baseline", "N_RLWE = N x r = " + std::to_string(N * r));
    } catch (const std::exception& e) {
        report_note("module pass failed", e.what());
    }
    release_contexts<DCRTModule>();
}

// ---------------------------------------------------------------------------
// Saved report: --out <path>
// ---------------------------------------------------------------------------
// Everything this program prints goes through std::cout, so the whole report
// can be teed to a file by swapping cout's stream buffer for one that forwards
// every character to the original buffer as well as to the file. stdout itself
// is untouched (same bytes, same order), and no report helper has to change.
class TeeBuf : public std::streambuf {
public:
    void attach(std::streambuf* primary, std::ostream& file) {
        primary_ = primary;
        file_ = &file;
    }

protected:
    int overflow(int c) override {
        if (c == traits_type::eof()) return traits_type::not_eof(c);
        file_->put(static_cast<char>(c));
        return primary_->sputc(static_cast<char>(c));
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        file_->write(s, n);
        return primary_->sputn(s, n);
    }
    int sync() override {
        file_->flush();
        return primary_->pubsync();
    }

private:
    std::streambuf* primary_ = nullptr;
    std::ostream* file_ = nullptr;
};

int main(int argc, char** argv) {
    // --out is specific to this program, so pull it out before the shared
    // parser sees the arguments; the loop flags keep working unchanged.
    std::string out_path;
    std::vector<std::string> rest;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--out") {
            if (i + 1 >= argc) {
                std::cerr << "error: --out needs a path\n";
                return 1;
            }
            out_path = argv[++i];
        } else {
            rest.push_back(arg);
        }
    }

    std::vector<char*> rest_argv;
    rest_argv.push_back(argv[0]);
    for (std::string& s : rest) rest_argv.push_back(const_cast<char*>(s.c_str()));

    // Document the extra option next to the shared ones when --help is asked for.
    for (const std::string& s : rest)
        if (s == "--help" || s == "-h")
            std::cout << "options: --out PATH (write the report to PATH as well as stdout)\n";

    const int flag_status = parse_loop_flags((int)rest_argv.size(), rest_argv.data());
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;

    // Open the report file and start teeing, before the first line is printed.
    std::ofstream report_file;
    TeeBuf tee;
    std::streambuf* const cout_buf = std::cout.rdbuf();
    if (!out_path.empty()) {
        report_file.open(out_path, std::ios::out | std::ios::trunc);
        if (!report_file) {
            std::cerr << "error: cannot open '" << out_path << "' for writing\n";
            return 1;
        }
        tee.attach(cout_buf, report_file);
        std::cout.rdbuf(&tee);
    }

    g_initial_ram_gb = get_available_ram_gb();

    std::cout << "FINDINGS\nThe points the paper leaves open, demonstrated in code.\n";
    std::cout << "available RAM: " << fmt(g_initial_ram_gb, 1) << " GB\n";

    finding_modulus_chain();
    finding_special_modulus();
    finding_precision_chain();
    finding_baseline_dimension();

    std::cout << "\ndone.\n";
    std::cout.flush();
    // Stop teeing: restore the original buffer last, so the closing lines above
    // reach the file too.
    if (!out_path.empty()) std::cout.rdbuf(cout_buf);
    return 0;
}
