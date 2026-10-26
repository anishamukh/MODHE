#include "benchmark_common.hpp"

// Real-world circuit: six chained multiply-relinearize-rescale steps on packed
// vectors, comparing the three approaches.

void run_eval(std::string name, int L, int N, int r, int r_ext, int mu, std::ofstream& csv) {
    const int d = L + 2;

    int target_dim = N * r;
    int N_rlwe = 1;
    while (N_rlwe < target_dim) N_rlwe *= 2;

    RamGuard guard = calculate_ram_guard(L, N, N_rlwe, r, r_ext, mu, g_initial_ram_gb);

    double time_rlwe = -1.0, time_modhe = -1.0, time_dpad = -1.0;
    double ram_rlwe = -1.0, ram_modhe = -1.0, ram_dpad = -1.0;
    double key_rlwe_meas = -1.0, key_modhe_meas = -1.0, key_dpad_meas = -1.0;
    std::string out_rlwe = "N/A", out_modhe = "N/A", out_dpad = "N/A";

    const std::vector<double> X = {0.02, 0.06, 0.03, 0.94, 0.21, 0.45, 0.76, 0.12};
    const std::vector<double> W = {0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5};
    const int CIRCUIT_DEPTH = 6;

    MemProfiler profiler;

    if (guard.run_rlwe) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_rlwe_context(L, N_rlwe, d);
            key_rlwe_meas = context_key_gb<DCRTPoly>();
            Plaintext p_X = ctx.cc->MakeCKKSPackedPlaintext(X);
            Plaintext p_W = ctx.cc->MakeCKKSPackedPlaintext(W);
            std::vector<double> run_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_time = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct_X = ctx.cc->Encrypt(ctx.keys.publicKey, p_X);
                    auto ct_W = ctx.cc->Encrypt(ctx.keys.publicKey, p_W);
                    auto ct_curr = ct_X;
                    auto t0 = Clock::now();
                    for (int i = 0; i < CIRCUIT_DEPTH; i++) {
                        auto ct_tensor = ctx.cc->EvalMultNoRelin(ct_curr, ct_W);
                        ct_curr = ctx.cc->Relinearize(ct_tensor);
                        ct_curr = ctx.cc->Rescale(ct_curr);
                    }
                    auto t1 = Clock::now();
                    sum_time += elapsed_ms(t0, t1);
                    if (run == RUNS_PER_TEST - 1 && iter == 0) {
                        try {
                            Plaintext res;
                            ctx.cc->Decrypt(ctx.keys.secretKey, ct_curr, &res);
                            res->SetLength(1);
                            out_rlwe = fmt(res->GetRealPackedValue()[0], 4);
                        } catch (...) { out_rlwe = "NOISE"; }
                    }
                }
                run_means.push_back(sum_time / ITERATIONS_PER_RUN);
            }
            time_rlwe = median(run_means);
        }
        ram_rlwe = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_rlwe < 0) ram_rlwe = 0.01;
        release_contexts<DCRTPoly>();
    }

    if (guard.run_modhe) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_modhe_context(L, N, r, d);
            key_modhe_meas = context_key_gb<DCRTModule>();
            Plaintext p_X = ctx.cc->MakeCKKSPackedPlaintext(X);
            Plaintext p_W = ctx.cc->MakeCKKSPackedPlaintext(W);
            std::vector<double> run_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_time = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct_X = ctx.cc->Encrypt(ctx.keys.publicKey, p_X);
                    auto ct_W = ctx.cc->Encrypt(ctx.keys.publicKey, p_W);
                    auto ct_curr = ct_X;
                    auto t0 = Clock::now();
                    for (int i = 0; i < CIRCUIT_DEPTH; i++) {
                        auto ct_tensor = ctx.cc->EvalMultNoRelin(ct_curr, ct_W);
                        ct_curr = ctx.cc->Relinearize(ct_tensor);
                        ct_curr = ctx.cc->Rescale(ct_curr);
                    }
                    auto t1 = Clock::now();
                    sum_time += elapsed_ms(t0, t1);
                    if (run == RUNS_PER_TEST - 1 && iter == 0) {
                        try {
                            Plaintext res;
                            ctx.cc->Decrypt(ctx.keys.secretKey, ct_curr, &res);
                            res->SetLength(1);
                            out_modhe = fmt(res->GetRealPackedValue()[0], 4);
                        } catch (...) { out_modhe = "NOISE"; }
                    }
                }
                run_means.push_back(sum_time / ITERATIONS_PER_RUN);
            }
            time_modhe = median(run_means);
        }
        ram_modhe = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_modhe < 0) ram_modhe = 0.01;
        release_contexts<DCRTModule>();
    }

    if (guard.run_dpad) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_dpad_context(L, N, r, r_ext, d, mu);
            auto dpad_keys = generate_dpad_keys(ctx, r, r_ext);
            key_dpad_meas = dpad_keys_gb(dpad_keys);
            Plaintext p_X = ctx.cc_P->MakeCKKSPackedPlaintext(X);
            Plaintext p_W = ctx.cc_P->MakeCKKSPackedPlaintext(W);
            std::vector<double> run_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_time = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct_X = ctx.cc_P->Encrypt(ctx.keys.publicKey, p_X);
                    auto ct_W = ctx.cc_P->Encrypt(ctx.keys.publicKey, p_W);
                    auto ct_curr = ct_X;
                    auto t0 = Clock::now();
                    for (int i = 0; i < CIRCUIT_DEPTH; i++) {
                        auto ct_tensor = ctx.cc_P->EvalMultNoRelin(ct_curr, ct_W);
                        ct_curr = DPad_Relin(ctx, ct_tensor, dpad_keys, r, r_ext);
                        ct_curr = ctx.cc_P->Rescale(ct_curr);
                    }
                    auto t1 = Clock::now();
                    sum_time += elapsed_ms(t0, t1);
                    if (run == RUNS_PER_TEST - 1 && iter == 0) {
                        try {
                            Plaintext res;
                            ctx.cc_P->Decrypt(ctx.keys.secretKey, ct_curr, &res);
                            res->SetLength(1);
                            out_dpad = fmt(res->GetRealPackedValue()[0], 4);
                        } catch (...) { out_dpad = "NOISE"; }
                    }
                }
                run_means.push_back(sum_time / ITERATIONS_PER_RUN);
            }
            time_dpad = median(run_means);
        }
        ram_dpad = profiler.stop_and_get_gb() - baseline_ram;
        if (ram_dpad < 0) ram_dpad = 0.01;
        release_contexts<DCRTModule>();
    }

    std::ostringstream params;
    params << "L=" << L << "  r=" << r << "  N=" << N
           << "  r_ext=" << r_ext << "  mu=" << mu;
    report_header(name, params.str());
    report_row("key    meas (GB)", fmt_or_na(key_rlwe_meas, 4),
               fmt_or_na(key_modhe_meas, 4), fmt_or_na(key_dpad_meas, 4));
    report_row("key    est  (GB)", fmt(guard.rlwe_key_gb, 4),
               fmt(guard.modhe_key_gb, 4), fmt(guard.dpad_key_gb, 4));
    report_row("time   (ms)", cell(guard.run_rlwe, time_rlwe, 1),
               cell(guard.run_modhe, time_modhe, 1), cell(guard.run_dpad, time_dpad, 1));
    report_row("ram    (GB)", cell(guard.run_rlwe, ram_rlwe, 3),
               cell(guard.run_modhe, ram_modhe, 3), cell(guard.run_dpad, ram_dpad, 3));
    report_row("output", guard.run_rlwe ? out_rlwe : std::string("denied"),
               guard.run_modhe ? out_modhe : std::string("denied"),
               guard.run_dpad ? out_dpad : std::string("denied"));

    csv << name << "," << L << "," << N << "," << d << "," << r << "," << r_ext << "," << mu << ","
        << fmt(csv_field(guard.run_rlwe, key_rlwe_meas), 4) << ","
        << fmt(csv_field(guard.run_modhe, key_modhe_meas), 4) << ","
        << fmt(csv_field(guard.run_dpad, key_dpad_meas), 4) << ","
        << fmt(guard.rlwe_key_gb, 4) << "," << fmt(guard.modhe_key_gb, 4) << "," << fmt(guard.dpad_key_gb, 4) << ","
        << fmt(csv_field(guard.run_rlwe, time_rlwe), 1) << ","
        << fmt(csv_field(guard.run_modhe, time_modhe), 1) << ","
        << fmt(csv_field(guard.run_dpad, time_dpad), 1) << ","
        << fmt(csv_field(guard.run_rlwe, ram_rlwe), 3) << ","
        << fmt(csv_field(guard.run_modhe, ram_modhe), 3) << ","
        << fmt(csv_field(guard.run_dpad, ram_dpad), 3) << "\n";
    csv.flush();
}

int main(int argc, char** argv) {
    const int flag_status = parse_loop_flags(argc, argv);
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;
    g_initial_ram_gb = get_available_ram_gb();
    std::ofstream csv("../results/circuit_results.csv");
    csv << "TaskName,L,N,d,r,r_ext,mu,"
           "Key_RLWE_GB,Key_Mod_GB,Key_DPad_GB,"
           "KeyEst_RLWE_GB,KeyEst_Mod_GB,KeyEst_DPad_GB,"
           "Time_RLWE_ms,Time_Mod_ms,Time_DPad_ms,"
           "RAM_RLWE_GB,RAM_Mod_GB,RAM_DPad_GB\n";

    std::cout << "RLWE-CKKS vs ModHE vs DPad-HE - multiplicative circuit (depth "
              << "6, median of " << RUNS_PER_TEST << " runs x " << ITERATIONS_PER_RUN
              << " iterations)\n";

    run_eval("Circuit_L9 (r=2)",  9, 16384, 2, 4, 4, csv);
    run_eval("Circuit_L14 (r=3)", 14, 16384, 3, 5, 4, csv);
    run_eval("Circuit_L19 (r=4)", 19, 8192, 4, 6, 5, csv);
    run_eval("Circuit_L25 (r=5)", 25, 8192, 5, 7, 5, csv);
    run_eval("Circuit_L30 (r=6)", 30, 8192, 6, 8, 5, csv);

    return 0;
}
