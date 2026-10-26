#include "benchmark_common.hpp"

// Standalone component timings: each relinearization phase measured on its own.

int main(int argc, char** argv) {
    const int flag_status = parse_loop_flags(argc, argv);
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;
    g_initial_ram_gb = get_available_ram_gb();
    std::cout << "Standalone relinearization components\n";

    std::ofstream csv("../results/relin_breakdown_results.csv");
    csv << "Rank,ModHE_Relin_ms,ModHE_RankDown_ms,DPad_RankUp_ms,DPad_RankDown_ms,DPad_Total_Relin_ms\n";

    const uint32_t scaleModSize = 40;
    const uint32_t batchSize = 8;
    const int ringDim = 8192;

    // Paper Table 3 (n = 2^13), indexed by base rank r. r_ext is the sloppy /
    // rank-up rank, mu the large-digit count of its context.
    const std::vector<int> multDepthByRank = {0, 0,  8, 13, 19, 25, 30, 35, 41};
    const std::vector<int> rExtByRank      = {0, 0,  3,  4,  5,  7,  8,  9, 10};
    const std::vector<int> muByRank        = {0, 0,  2,  3,  4,  3,  4,  4,  5};

    for (int r = 2; r <= 8; r++) {
        const int multDepth = multDepthByRank[r];
        const int r_ext = rExtByRank[r];
        const int mu = muByRank[r];

        RamGuard guard = calculate_ram_guard(multDepth, ringDim, ringDim, r, r_ext, mu, g_initial_ram_gb);

        std::ostringstream params;
        params << "L=" << multDepth << "  r=" << r << "  N=" << ringDim
               << "  r_ext=" << r_ext << "  mu=" << mu;
        report_header("rank " + std::to_string(r), params.str());

        // Strict context (ModHE): full d digits at base rank r.
        CCParams<CryptoContextCKKSMod> params_strict;
        params_strict.SetMultiplicativeDepth(multDepth);
        params_strict.SetScalingModSize(scaleModSize);
        params_strict.SetFirstModSize(60);
        params_strict.SetBatchSize(batchSize);
        params_strict.SetRingDim(ringDim);
        params_strict.SetModuleRank(r);
        params_strict.SetNumLargeDigits(multDepth + 2); // d = L + 2
        params_strict.SetSecurityLevel(HEStd_NotSet);
        auto cc_strict = GenCryptoContext(params_strict);
        cc_strict->Enable(PKE); cc_strict->Enable(KEYSWITCH); cc_strict->Enable(LEVELEDSHE);

        auto keys_strict = cc_strict->KeyGen();
        if (guard.run_modhe) cc_strict->EvalMultModKeyGen(keys_strict.secretKey);

        // Sloppy context (DPad rank-up): rank r_ext, mu large digits.
        CCParams<CryptoContextCKKSMod> params_sloppy;
        params_sloppy.SetMultiplicativeDepth(multDepth);
        params_sloppy.SetScalingModSize(scaleModSize);
        params_sloppy.SetFirstModSize(60);
        params_sloppy.SetBatchSize(batchSize);
        params_sloppy.SetRingDim(ringDim);
        params_sloppy.SetModuleRank(r_ext);
        params_sloppy.SetNumLargeDigits(mu); // numDigitsSloppy
        params_sloppy.SetSecurityLevel(HEStd_NotSet);
        auto cc_sloppy = GenCryptoContext(params_sloppy);
        cc_sloppy->Enable(PKE); cc_sloppy->Enable(KEYSWITCH); cc_sloppy->Enable(LEVELEDSHE);

        lbcrypto::dpad::DPadKeys dpad_keys;
        if (guard.run_dpad)
            dpad_keys = lbcrypto::dpad::generate_dpad_keys(cc_sloppy, cc_strict, keys_strict.secretKey, r, r_ext);

        // ModHE native rank-down key (r_ext -> r), on the sloppy context.
        auto keys_sloppy = cc_sloppy->KeyGen();
        PrivateKey<DCRTModule> reducedKey;
        lbcrypto::EvalKey<lbcrypto::DCRTModule> modhe_rankred_key;
        if (guard.run_modhe)
            modhe_rankred_key = cc_sloppy->EvalRankRedKeyGen(keys_sloppy.secretKey, reducedKey, r);

        // Ciphertexts prepared once, outside the timing loops.
        const std::vector<double> in1 = {0.5, 0.7};
        const std::vector<double> in2 = {0.2, 0.3};
        auto ct_strict1 = cc_strict->Encrypt(keys_strict.publicKey, cc_strict->MakeCKKSPackedPlaintext(in1));
        auto ct_strict2 = cc_strict->Encrypt(keys_strict.publicKey, cc_strict->MakeCKKSPackedPlaintext(in2));
        auto ct_sloppy1 = cc_sloppy->Encrypt(keys_sloppy.publicKey, cc_sloppy->MakeCKKSPackedPlaintext(in1));
        auto ct_tensor = cc_strict->EvalMultNoRelin(ct_strict1, ct_strict2); // ModHE tensor

        std::pair<DCRTModule, DCRTModule> rank_up_parts;
        if (guard.run_dpad)
            rank_up_parts = lbcrypto::dpad::DPad_RankUp(cc_sloppy, ct_tensor, dpad_keys);

        std::vector<double> modhe_relin_runs, modhe_rankdown_runs, dpad_up_runs, dpad_down_runs;

        for (int run = 0; run < RUNS_PER_TEST; run++) {
            double sum_modhe_relin = 0.0, sum_modhe_rankdown = 0.0;
            double sum_dpad_up = 0.0, sum_dpad_down = 0.0;

            for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                if (guard.run_modhe) {
                    auto t0 = Clock::now();
                    auto ct_relin = cc_strict->Relinearize(ct_tensor);
                    auto t1 = Clock::now();
                    sum_modhe_relin += elapsed_ms(t0, t1);

                    t0 = Clock::now();
                    auto ct_modhe_rd = cc_sloppy->EvalRankReduce(ct_sloppy1, modhe_rankred_key);
                    t1 = Clock::now();
                    sum_modhe_rankdown += elapsed_ms(t0, t1);
                }
                if (guard.run_dpad) {
                    auto t0 = Clock::now();
                    auto rank_up_local = lbcrypto::dpad::DPad_RankUp(cc_sloppy, ct_tensor, dpad_keys);
                    auto t1 = Clock::now();
                    sum_dpad_up += elapsed_ms(t0, t1);
                    (void)rank_up_local;

                    t0 = Clock::now();
                    auto ct_dpad = lbcrypto::dpad::DPad_RankDown(cc_strict, ct_tensor, dpad_keys,
                                                                 rank_up_parts.first, rank_up_parts.second, r, r_ext);
                    t1 = Clock::now();
                    sum_dpad_down += elapsed_ms(t0, t1);
                }
            }
            modhe_relin_runs.push_back(sum_modhe_relin / ITERATIONS_PER_RUN);
            modhe_rankdown_runs.push_back(sum_modhe_rankdown / ITERATIONS_PER_RUN);
            dpad_up_runs.push_back(sum_dpad_up / ITERATIONS_PER_RUN);
            dpad_down_runs.push_back(sum_dpad_down / ITERATIONS_PER_RUN);
        }

        double avg_modhe_relin = guard.run_modhe ? median(modhe_relin_runs) : -1.0;
        double avg_modhe_rankdown = guard.run_modhe ? median(modhe_rankdown_runs) : -1.0;
        double avg_dpad_up = guard.run_dpad ? median(dpad_up_runs) : -1.0;
        double avg_dpad_down = guard.run_dpad ? median(dpad_down_runs) : -1.0;
        double avg_dpad_total = guard.run_dpad ? avg_dpad_up + avg_dpad_down : -1.0;

        report_note("ModHE relin (ms)", cell(guard.run_modhe, avg_modhe_relin));
        report_note("ModHE rankdown (ms)", cell(guard.run_modhe, avg_modhe_rankdown));
        report_note("DPad  rankup (ms)", cell(guard.run_dpad, avg_dpad_up));
        report_note("DPad  rankdown (ms)", cell(guard.run_dpad, avg_dpad_down));
        report_note("DPad  total (ms)", cell(guard.run_dpad, avg_dpad_total));

        csv << r << "," << fmt(avg_modhe_relin, 2) << "," << fmt(avg_modhe_rankdown, 2) << ","
            << fmt(avg_dpad_up, 2) << "," << fmt(avg_dpad_down, 2) << ","
            << fmt(avg_dpad_total, 2) << "\n";
        csv.flush();

        release_contexts<DCRTModule>();
    }

    std::cout << "Saved to ../results/relin_breakdown_results.csv\n";
    return 0;
}