#include "benchmark_common.hpp"

// Two timing columns per algorithm: Time_*_ms is the relinearization step alone,
// Time_*_hmult_rescale_ms is the full HMult + Relinearize + Rescale block.
// Precision is not measured here; benchmark_precision owns the Prec_* columns.
static constexpr size_t PROBE_SLOTS = 8;

void fill_probe(std::vector<double>& x1, std::vector<double>& x2) {
    x1.resize(PROBE_SLOTS);
    x2.resize(PROBE_SLOTS);
    for (size_t i = 0; i < PROBE_SLOTS; ++i) {
        x1[i] = 0.1 * (double)(i + 1);
        x2[i] = 0.2 * (double)(i + 1);
    }
}

void run_eval(std::string name, int L, int N, int r, int r_ext, int mu, std::ofstream& csv) {
    const int d = L + 2; // Q prime count: L + 1 depth primes + one extra modulus (FLEXIBLEAUTOEXT)

    int target_dim = N * r;
    int N_rlwe = 1;
    while (N_rlwe < target_dim) N_rlwe *= 2;

    RamGuard guard = calculate_ram_guard(L, N, N_rlwe, r, r_ext, mu, g_initial_ram_gb);

    std::ostringstream params;
    params << "L=" << L << "  r=" << r << "  N=" << N
           << "  r_ext=" << r_ext << "  mu=" << mu;
    report_header(name, params.str());

    if (!guard.run_rlwe && !guard.run_modhe && !guard.run_dpad) {
        report_note("status", "all algorithms denied by the RAM guard");
        report_row("key est (GB)", fmt(guard.rlwe_key_gb, 4),
                   fmt(guard.modhe_key_gb, 4), fmt(guard.dpad_key_gb, 4));
        csv << name << "," << L << "," << d << "," << r << "," << N << "," << N_rlwe << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << ","
            << guard.rlwe_key_gb << "," << guard.modhe_key_gb << "," << guard.dpad_key_gb << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << ","
            << -1.0 << "," << -1.0 << "\n";
        return;
    }

    double time_rlwe = -1.0, time_modhe = -1.0, time_dpad = -1.0;
    double hmult_rlwe = -1.0, hmult_modhe = -1.0, hmult_dpad = -1.0;
    double ram_rlwe = -1.0, ram_modhe = -1.0, ram_dpad = -1.0;
    double key_rlwe_meas = -1.0, key_modhe_meas = -1.0, key_dpad_meas = -1.0;

    std::vector<double> x1, x2;
    fill_probe(x1, x2);

    MemProfiler profiler;

    // ---------------- RLWE-CKKS ----------------
    if (guard.run_rlwe) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_rlwe_context(L, N_rlwe, d);
            key_rlwe_meas = context_key_gb<DCRTPoly>();
            Plaintext p1 = ctx.cc->MakeCKKSPackedPlaintext(x1);
            Plaintext p2 = ctx.cc->MakeCKKSPackedPlaintext(x2);
            std::vector<double> relin_means, block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_relin = 0.0, sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey, p2);
                    auto ct_tensor = ctx.cc->EvalMultNoRelin(ct1, ct2);
                    auto t0 = Clock::now();
                    auto ct_relin = ctx.cc->Relinearize(ct_tensor);
                    auto t1 = Clock::now();
                    sum_relin += elapsed_ms(t0, t1);

                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc->EvalMultAndRelinearize(ct1, ct2);
                    ct_block = ctx.cc->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                relin_means.push_back(sum_relin / ITERATIONS_PER_RUN);
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            time_rlwe = median(relin_means);
            hmult_rlwe = median(block_means);
        }
        ram_rlwe = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_rlwe < 0) ram_rlwe = 0.01;
        release_contexts<DCRTPoly>();
    }

    // ---------------- ModHE ----------------
    if (guard.run_modhe) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_modhe_context(L, N, r, d);
            key_modhe_meas = context_key_gb<DCRTModule>();
            Plaintext p1 = ctx.cc->MakeCKKSPackedPlaintext(x1);
            Plaintext p2 = ctx.cc->MakeCKKSPackedPlaintext(x2);
            std::vector<double> relin_means, block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_relin = 0.0, sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey, p2);
                    auto ct_tensor = ctx.cc->EvalMultNoRelin(ct1, ct2);
                    auto t0 = Clock::now();
                    auto ct_relin = ctx.cc->Relinearize(ct_tensor);
                    auto t1 = Clock::now();
                    sum_relin += elapsed_ms(t0, t1);

                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc->EvalMultNoRelin(ct1, ct2);
                    ct_block = ctx.cc->Relinearize(ct_block);
                    ct_block = ctx.cc->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                relin_means.push_back(sum_relin / ITERATIONS_PER_RUN);
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            time_modhe = median(relin_means);
            hmult_modhe = median(block_means);
        }
        ram_modhe = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_modhe < 0) ram_modhe = 0.01;
        release_contexts<DCRTModule>();
    }

    // ---------------- DPad-HE ----------------
    if (guard.run_dpad) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_dpad_context(L, N, r, r_ext, d, mu);
            auto dpad_keys = generate_dpad_keys(ctx, r, r_ext);
            key_dpad_meas = dpad_keys_gb(dpad_keys);
            std::vector<double> relin_means, block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_relin = 0.0, sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    Plaintext p1 = ctx.cc_P->MakeCKKSPackedPlaintext(x1);
                    Plaintext p2 = ctx.cc_P->MakeCKKSPackedPlaintext(x2);
                    auto ct1 = ctx.cc_P->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc_P->Encrypt(ctx.keys.publicKey, p2);
                    auto ct_tensor = ctx.cc_P->EvalMultNoRelin(ct1, ct2);
                    auto t0 = Clock::now();
                    auto ct_relin = DPad_Relin(ctx, ct_tensor, dpad_keys, r, r_ext);
                    auto t1 = Clock::now();
                    sum_relin += elapsed_ms(t0, t1);

                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc_P->EvalMultNoRelin(ct1, ct2);
                    ct_block = DPad_Relin(ctx, ct_block, dpad_keys, r, r_ext);
                    ct_block = ctx.cc_P->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                relin_means.push_back(sum_relin / ITERATIONS_PER_RUN);
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            time_dpad = median(relin_means);
            hmult_dpad = median(block_means);
        }
        ram_dpad = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_dpad < 0) ram_dpad = 0.01;
        release_contexts<DCRTModule>();
    }

    // ---------------- per-test report ----------------
    report_row("key    meas (GB)", fmt_or_na(key_rlwe_meas, 4),
               fmt_or_na(key_modhe_meas, 4), fmt_or_na(key_dpad_meas, 4));
    report_row("key    est  (GB)", fmt(guard.rlwe_key_gb, 4),
               fmt(guard.modhe_key_gb, 4), fmt(guard.dpad_key_gb, 4));
    report_row("time   relin (ms)", cell(guard.run_rlwe, time_rlwe, 1),
               cell(guard.run_modhe, time_modhe, 1), cell(guard.run_dpad, time_dpad, 1));
    report_row("time   hmult+rescale (ms)", cell(guard.run_rlwe, hmult_rlwe, 1),
               cell(guard.run_modhe, hmult_modhe, 1), cell(guard.run_dpad, hmult_dpad, 1));
    report_row("ram    (GB)", cell(guard.run_rlwe, ram_rlwe, 3),
               cell(guard.run_modhe, ram_modhe, 3), cell(guard.run_dpad, ram_dpad, 3));

    std::string speedup = "N/A";
    if (guard.run_modhe && guard.run_dpad && time_dpad > 0)
        speedup = fmt(time_modhe / time_dpad, 2) + "x";
    report_note("speedup relin (ModHE/DPad)", speedup);
    std::string speedup_hmult = "N/A";
    if (guard.run_modhe && guard.run_dpad && hmult_dpad > 0)
        speedup_hmult = fmt(hmult_modhe / hmult_dpad, 2) + "x";
    report_note("speedup hmult+rescale", speedup_hmult);

    const double speedup_relin_val =
        (guard.run_modhe && guard.run_dpad && time_dpad > 0) ? time_modhe / time_dpad : -1.0;
    const double speedup_hmult_val =
        (guard.run_modhe && guard.run_dpad && hmult_dpad > 0) ? hmult_modhe / hmult_dpad : -1.0;

    csv << name << "," << L << "," << d << "," << r << "," << N << "," << N_rlwe << ","
        << fmt(csv_field(guard.run_rlwe, key_rlwe_meas), 4) << ","
        << fmt(csv_field(guard.run_modhe, key_modhe_meas), 4) << ","
        << fmt(csv_field(guard.run_dpad, key_dpad_meas), 4) << ","
        << fmt(guard.rlwe_key_gb, 4) << "," << fmt(guard.modhe_key_gb, 4) << "," << fmt(guard.dpad_key_gb, 4) << ","
        << fmt(csv_field(guard.run_rlwe, ram_rlwe), 3) << ","
        << fmt(csv_field(guard.run_modhe, ram_modhe), 3) << ","
        << fmt(csv_field(guard.run_dpad, ram_dpad), 3) << ","
        << fmt(csv_field(guard.run_rlwe, time_rlwe), 1) << ","
        << fmt(csv_field(guard.run_modhe, time_modhe), 1) << ","
        << fmt(csv_field(guard.run_dpad, time_dpad), 1) << ","
        << fmt(csv_field(guard.run_rlwe, hmult_rlwe), 1) << ","
        << fmt(csv_field(guard.run_modhe, hmult_modhe), 1) << ","
        << fmt(csv_field(guard.run_dpad, hmult_dpad), 1) << ","
        << fmt(speedup_relin_val, 3) << "," << fmt(speedup_hmult_val, 3) << "\n";
    csv.flush();
}

int main(int argc, char** argv) {
    const int flag_status = parse_loop_flags(argc, argv);
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;
    std::ofstream csv("../results/hmult_rescale_results.csv");
    csv << "TestName,L,d,r,N,N_RLWE,"
           "Key_RLWE_GB,Key_Mod_GB,Key_DPad_GB,"
           "KeyEst_RLWE_GB,KeyEst_Mod_GB,KeyEst_DPad_GB,"
           "RAM_RLWE_GB,RAM_Mod_GB,RAM_DPad_GB,"
           "Time_RLWE_ms,Time_Mod_ms,Time_DPad_ms,"
           "Time_RLWE_hmult_rescale_ms,Time_Mod_hmult_rescale_ms,Time_DPad_hmult_rescale_ms,"
           "Speedup_Relin,Speedup_HMultRescale\n";
    g_initial_ram_gb = get_available_ram_gb();

    std::cout << "RLWE-CKKS vs ModHE vs DPad-HE\n";
    std::cout << "median of " << RUNS_PER_TEST << " runs x " << ITERATIONS_PER_RUN
              << " iterations\n";
    std::cout << "RAM guard: run only if estimated peak < available - "
              << fmt(RAM_SAFETY_BUFFER_GB, 1) << " GB  (available: "
              << fmt(g_initial_ram_gb, 1) << " GB)\n";

    // Paper Table 3 (n = 2^13): r is the base rank, r_ext the sloppy rank, mu
    // its large-digit count, reconstructed as ceil((L+1)/(K+1)) with K the
    // 55-bit prime count in log2 P_hat = 60 + 55 x K; see README.md.
    run_eval("Paper_Scale_L8_r2",  8, 8192, 2,  3, 2, csv);
    run_eval("Paper_Scale_L13_r3", 13, 8192, 3,  4, 3, csv);
    run_eval("Paper_Scale_L19_r4", 19, 8192, 4,  5, 4, csv);
    run_eval("Paper_Scale_L25_r5", 25, 8192, 5,  7, 3, csv);
    run_eval("Paper_Scale_L30_r6", 30, 8192, 6,  8, 4, csv);
    run_eval("Paper_Scale_L35_r7", 35, 8192, 7,  9, 4, csv);
    run_eval("Paper_Scale_L41_r8", 41, 8192, 8, 10, 5, csv);

    // Custom test cases: run_eval("Test_Name", L, N, r, r_ext, mu, csv), fields
    // as in the Paper_Scale block above. Names stay within 24 characters so the
    // CSV column and the plots line up.

    // START


    // END

    return 0;
}
