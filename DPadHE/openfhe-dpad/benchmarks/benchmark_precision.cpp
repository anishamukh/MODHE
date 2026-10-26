#include "benchmark_common.hpp"

// Precision benchmark (paper Sec. 5, RQ2): one multiplication per configuration on a
// fresh context, at the same chain point benchmark_hmult_rescale.cpp samples. Run twice
// per configuration: Prec_* is OpenFHE's error estimate, L2_* the paper's formula on the
// decoded slots; both pack a full plaintext. README.md holds the details.
//
// The repetition count is the probe count (ERROR_RUNS, default 10, set by --loops when given).
inline int ERROR_RUNS = 10;

// Distinct values in the probe; the plaintext repeats them over every slot.
static constexpr size_t BASE_SLOTS = 8;

void fill_probe(std::vector<double>& x1, std::vector<double>& x2, std::vector<double>& expected,
                size_t slots) {
    x1.resize(slots);
    x2.resize(slots);
    expected.resize(slots);
    for (size_t i = 0; i < slots; ++i) {
        x1[i] = 0.1 * (double)((i % BASE_SLOTS) + 1);
        x2[i] = 0.2 * (double)((i % BASE_SLOTS) + 1);
        expected[i] = x1[i] * x2[i];
    }
}

// One pass over ERROR_RUNS probes of the chain in one execution mode. Returns the
// worst case (smallest) precision over the probes, "INF" for an exact result, or
// "N/A" when the scheme does not support the mode.
template <typename CC, typename KP, typename RelinFn>
std::string chain_precision(const CC& cc, const KP& keys, ExecutionMode mode,
                            const std::vector<double>& x1, const std::vector<double>& x2,
                            const std::vector<double>& expected, RelinFn relin) {
    try {
        Plaintext p1 = cc->MakeCKKSPackedPlaintext(x1);
        Plaintext p2 = cc->MakeCKKSPackedPlaintext(x2);
        std::vector<double> precisions;
        for (int run = 0; run < ERROR_RUNS; run++) {
            auto ct1 = cc->Encrypt(keys.publicKey, p1);
            auto ct2 = cc->Encrypt(keys.publicKey, p2);
            auto ct_tensor = cc->EvalMultNoRelin(ct1, ct2);
            auto ct_final = relin(cc, ct_tensor);
            ct_final = cc->Rescale(ct_final);

            Plaintext res;
            cc->Decrypt(keys.secretKey, ct_final, &res);
            if (mode == EXEC_NOISE_ESTIMATION) {
                // An estimation decode sets no values; decoded slots here mean the
                // scheme ignored the mode, so the estimate would be the evaluation
                // value with its decoder noise.
                if (!res->GetRealPackedValue().empty()) return "N/A";
                precisions.push_back(res->GetLogPrecision());
            } else {
                const std::string p = precision_metric(expected, decrypted_slots(res, expected.size()));
                if (p == "INF") return "INF";
                precisions.push_back(std::stod(p));
            }
        }
        if (precisions.empty()) return "N/A";
        return fmt(min_value(precisions), 2);
    } catch (const std::exception& e) {
        std::cerr << "[precision] " << (mode == EXEC_NOISE_ESTIMATION ? "estimation" : "evaluation")
                  << " pass failed: " << e.what() << "\n";
        return "N/A";
    }
}

void run_eval(std::string name, int L, int N, int r, int r_ext, int mu, std::ofstream& csv) {
    const int d = L + 2; // Q prime count incl. the FLEXIBLEAUTOEXT extra modulus

    int target_dim = N * r;
    int N_rlwe = 1;
    while (N_rlwe < target_dim) N_rlwe *= 2;

    RamGuard guard = calculate_ram_guard(L, N, N_rlwe, r, r_ext, mu, g_initial_ram_gb);

    // A plaintext holds one slot per ring element of the context it is packed on,
    // so the RLWE context (ring dimension N_rlwe) takes a longer vector than the
    // ModHE and DPad contexts (ring dimension N).
    std::vector<double> x1_rlwe, x2_rlwe, expected_rlwe;
    std::vector<double> x1, x2, expected;
    fill_probe(x1_rlwe, x2_rlwe, expected_rlwe, (size_t)N_rlwe / 2);
    fill_probe(x1, x2, expected, (size_t)N / 2);

    std::string prec_rlwe = "N/A", prec_modhe = "N/A", prec_dpad = "N/A";
    std::string l2_rlwe = "N/A", l2_modhe = "N/A", l2_dpad = "N/A";

    if (guard.run_rlwe) {
        const auto relin = [](const auto& cc, auto& ct) { return cc->Relinearize(ct); };
        {
            auto ctx = setup_rlwe_context(L, N_rlwe, d);
            l2_rlwe = chain_precision(ctx.cc, ctx.keys, EXEC_EVALUATION, x1_rlwe, x2_rlwe, expected_rlwe, relin);
            release_contexts<DCRTPoly>();
        }
        {
            auto ctx = setup_rlwe_context(L, N_rlwe, d, EXEC_NOISE_ESTIMATION);
            prec_rlwe = chain_precision(ctx.cc, ctx.keys, EXEC_NOISE_ESTIMATION, x1_rlwe, x2_rlwe, expected_rlwe, relin);
            release_contexts<DCRTPoly>();
        }
    }

    if (guard.run_modhe) {
        const auto relin = [](const auto& cc, auto& ct) { return cc->Relinearize(ct); };
        {
            auto ctx = setup_modhe_context(L, N, r, d);
            l2_modhe = chain_precision(ctx.cc, ctx.keys, EXEC_EVALUATION, x1, x2, expected, relin);
            release_contexts<DCRTModule>();
        }
        {
            auto ctx = setup_modhe_context(L, N, r, d, EXEC_NOISE_ESTIMATION);
            prec_modhe = chain_precision(ctx.cc, ctx.keys, EXEC_NOISE_ESTIMATION, x1, x2, expected, relin);
            release_contexts<DCRTModule>();
        }
    }

    if (guard.run_dpad) {
        {
            auto ctx = setup_dpad_context(L, N, r, r_ext, d, mu);
            auto dpad_keys = generate_dpad_keys(ctx, r, r_ext);
            const auto relin = [&ctx, &dpad_keys, r, r_ext](const auto& cc, auto& ct) {
                return DPad_Relin(ctx, ct, dpad_keys, r, r_ext);
            };
            l2_dpad = chain_precision(ctx.cc_P, ctx.keys, EXEC_EVALUATION, x1, x2, expected, relin);
            release_contexts<DCRTModule>();
        }
        {
            auto ctx = setup_dpad_context(L, N, r, r_ext, d, mu, EXEC_NOISE_ESTIMATION);
            auto dpad_keys = generate_dpad_keys(ctx, r, r_ext);
            const auto relin = [&ctx, &dpad_keys, r, r_ext](const auto& cc, auto& ct) {
                return DPad_Relin(ctx, ct, dpad_keys, r, r_ext);
            };
            prec_dpad = chain_precision(ctx.cc_P, ctx.keys, EXEC_NOISE_ESTIMATION, x1, x2, expected, relin);
            release_contexts<DCRTModule>();
        }
    }

    // A refused run writes the -1 sentinel like every other benchmark; "N/A"
    // stays reserved for a value that was measured but is not meaningful.
    if (!guard.run_rlwe) prec_rlwe = l2_rlwe = "-1.00";
    if (!guard.run_modhe) prec_modhe = l2_modhe = "-1.00";
    if (!guard.run_dpad) prec_dpad = l2_dpad = "-1.00";

    std::ostringstream params;
    params << "L=" << L << "  r=" << r << "  N=" << N
           << "  r_ext=" << r_ext << "  mu=" << mu;
    report_header(name, params.str());
    report_row("precision (est)", guard.run_rlwe ? prec_rlwe : std::string("denied"),
               guard.run_modhe ? prec_modhe : std::string("denied"),
               guard.run_dpad ? prec_dpad : std::string("denied"));
    report_row("precision (l2)", guard.run_rlwe ? l2_rlwe : std::string("denied"),
               guard.run_modhe ? l2_modhe : std::string("denied"),
               guard.run_dpad ? l2_dpad : std::string("denied"));

    csv << name << "," << L << "," << d << "," << r << "," << N << "," << N_rlwe << ","
        << r_ext << "," << mu << ","
        << (guard.run_rlwe ? 1 : 0) << "," << (guard.run_modhe ? 1 : 0) << "," << (guard.run_dpad ? 1 : 0) << ","
        << prec_rlwe << "," << prec_modhe << "," << prec_dpad << ","
        << l2_rlwe << "," << l2_modhe << "," << l2_dpad << "\n";
    csv.flush();
}

int main(int argc, char** argv) {
    const int flag_status = parse_loop_flags(argc, argv);
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;
    // An explicit --loops becomes the probe count here too.
    if (LOOPS_OVERRIDE > 0) ERROR_RUNS = LOOPS_OVERRIDE;
    g_initial_ram_gb = get_available_ram_gb();
    std::ofstream csv("../results/precision_results.csv");
    csv << "TestName,L,d,r,N,N_RLWE,r_ext,mu,"
           "Run_RLWE,Run_Mod,Run_DPad,"
           "Prec_RLWE,Prec_Mod,Prec_DPad,"
           "L2_RLWE,L2_Mod,L2_DPad\n";

    std::cout << "ERROR BENCHMARK (precision in bits after EvalMult -> relin -> rescale)\n";
    std::cout << "  est = OpenFHE error estimate, l2 = decoded l2-norm (paper Sec. 5)\n";
    std::cout << "worst-case (smallest) precision of " << ERROR_RUNS
              << " probe(s) per configuration\n";

    // Series A — Paper Table 3 (n = 2^13): L grows with r, as in the Paper_Scale
    // cases of benchmark_hmult_rescale.cpp.
    std::cout << "\nSeries A: Paper Table 3 (L and r grow together)\n";
    run_eval("Paper_Scale_L8_r2",  8, 8192, 2,  3, 2, csv);
    run_eval("Paper_Scale_L13_r3", 13, 8192, 3,  4, 3, csv);
    run_eval("Paper_Scale_L19_r4", 19, 8192, 4,  5, 4, csv);
    run_eval("Paper_Scale_L25_r5", 25, 8192, 5,  7, 3, csv);
    run_eval("Paper_Scale_L30_r6", 30, 8192, 6,  8, 4, csv);
    run_eval("Paper_Scale_L35_r7", 35, 8192, 7,  9, 4, csv);
    run_eval("Paper_Scale_L41_r8", 41, 8192, 8, 10, 5, csv);

    // Series B — fixed depth, variable rank: L = 30 while r runs from 2 to 8, so
    // the precision curve reflects the rank alone. r_ext = r + 2 and mu = 5 fixed.
    std::cout << "\nSeries B: fixed L=30, variable rank\n";
    run_eval("FixedL30_r2", 30, 8192, 2,  4, 5, csv);
    run_eval("FixedL30_r3", 30, 8192, 3,  5, 5, csv);
    run_eval("FixedL30_r4", 30, 8192, 4,  6, 5, csv);
    run_eval("FixedL30_r5", 30, 8192, 5,  7, 5, csv);
    run_eval("FixedL30_r6", 30, 8192, 6,  8, 5, csv);
    run_eval("FixedL30_r7", 30, 8192, 7,  9, 5, csv);
    run_eval("FixedL30_r8", 30, 8192, 8, 10, 5, csv);

    return 0;
}
