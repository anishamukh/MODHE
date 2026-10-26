#include "benchmark_common.hpp"

// Paper Table 5 sets: same multiplicative depth, two ring dimensions (N = 2^15
// and 2^16), two module ranks each (r = 2 and r = 4). Table 6 reports the
// HMult+Rescale time, Table 7 the relinearization key size. RNS-CKKS (r = 1) is
// the baseline column in both tables, measured here by the RLWE context.
static constexpr size_t PROBE_SLOTS = 8;
static constexpr int TABLE5_DEPTH_SMALL = 19; // N = 2^15, log2 q = 60 + 40 x 19
static constexpr int TABLE5_DEPTH_LARGE = 41; // N = 2^16, log2 q = 60 + 40 x 41

void fill_probe(std::vector<double>& x1, std::vector<double>& x2) {
    x1.resize(PROBE_SLOTS);
    x2.resize(PROBE_SLOTS);
    for (size_t i = 0; i < PROBE_SLOTS; ++i) {
        x1[i] = 0.1 * (double)(i + 1);
        x2[i] = 0.2 * (double)(i + 1);
    }
}

// name  : test label (Set II/III/V/VI)
// L     : multiplicative depth (19 for N = 2^15, 41 for N = 2^16)
// N     : ModHE ring dimension n (2^14, 2^13, 2^15, 2^14)
// r     : base rank (2 or 4)
// r_ext : sloppy rank r_hat (3 or 5)
// mu    : large-digit count of the sloppy context, reconstructed as
//         ceil((L+1)/(K+1)) with K the 55-bit prime count in log2 P_hat
void run_eval(std::string name, int L, int N, int r, int r_ext, int mu, std::ofstream& csv) {
    const int d = L + 2; // Q prime count: L + 1 depth primes + one extra modulus (FLEXIBLEAUTOEXT)

    int target_dim = N * r;
    int N_rlwe = 1;
    while (N_rlwe < target_dim) N_rlwe *= 2;

    RamGuard guard = calculate_ram_guard(L, N, N_rlwe, r, r_ext, mu, g_initial_ram_gb);

    std::ostringstream params;
    params << "set " << name << "  L=" << L << "  r=" << r << "  n=" << N
           << "  r_ext=" << r_ext << "  mu=" << mu;
    report_header("Table5 " + name, params.str());

    if (!guard.run_rlwe && !guard.run_modhe && !guard.run_dpad) {
        report_note("status", "all algorithms denied by the RAM guard");
        report_row("key est (GB)", fmt(guard.rlwe_key_gb, 4),
                   fmt(guard.modhe_key_gb, 4), fmt(guard.dpad_key_gb, 4));
        csv << name << "," << L << "," << N << "," << N_rlwe << "," << r << "," << r_ext << "," << mu << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << ","
            << -1.0 << "," << -1.0 << ","
            << -1.0 << "," << -1.0 << "," << -1.0 << "," << -1.0 << "\n";
        return;
    }

    double hmult_rlwe = -1.0, hmult_modhe = -1.0, hmult_dpad = -1.0;
    double key_rlwe_meas = -1.0, key_modhe_meas = -1.0, key_dpad_meas = -1.0;

    std::vector<double> x1, x2;
    fill_probe(x1, x2);

    MemProfiler profiler;

    // ---------------- RNS-CKKS baseline (r = 1) ----------------
    if (guard.run_rlwe) {
        double baseline_ram = MemProfiler::get_current_rss_gb();
        profiler.start();
        {
            auto ctx = setup_rlwe_context(L, N_rlwe, d);
            key_rlwe_meas = context_key_gb<DCRTPoly>();
            Plaintext p1 = ctx.cc->MakeCKKSPackedPlaintext(x1);
            Plaintext p2 = ctx.cc->MakeCKKSPackedPlaintext(x2);
            std::vector<double> block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey, p2);
                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc->EvalMultAndRelinearize(ct1, ct2);
                    ct_block = ctx.cc->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            hmult_rlwe = median(block_means);
        }
        (void)profiler.stop_and_get_gb();
        release_contexts<DCRTPoly>();
    }

    // ---------------- ModHE ----------------
    if (guard.run_modhe) {
        profiler.start();
        {
            auto ctx = setup_modhe_context(L, N, r, d);
            key_modhe_meas = context_key_gb<DCRTModule>();
            Plaintext p1 = ctx.cc->MakeCKKSPackedPlaintext(x1);
            Plaintext p2 = ctx.cc->MakeCKKSPackedPlaintext(x2);
            std::vector<double> block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    auto ct1 = ctx.cc->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc->Encrypt(ctx.keys.publicKey, p2);
                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc->EvalMultNoRelin(ct1, ct2);
                    ct_block = ctx.cc->Relinearize(ct_block);
                    ct_block = ctx.cc->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            hmult_modhe = median(block_means);
        }
        (void)profiler.stop_and_get_gb();
        release_contexts<DCRTModule>();
    }

    // ---------------- DPad-HE ----------------
    if (guard.run_dpad) {
        profiler.start();
        {
            auto ctx = setup_dpad_context(L, N, r, r_ext, d, mu);
            auto dpad_keys = generate_dpad_keys(ctx, r, r_ext);
            key_dpad_meas = dpad_keys_gb(dpad_keys);
            std::vector<double> block_means;
            for (int run = 0; run < RUNS_PER_TEST; run++) {
                double sum_block = 0.0;
                for (int iter = 0; iter < ITERATIONS_PER_RUN; iter++) {
                    Plaintext p1 = ctx.cc_P->MakeCKKSPackedPlaintext(x1);
                    Plaintext p2 = ctx.cc_P->MakeCKKSPackedPlaintext(x2);
                    auto ct1 = ctx.cc_P->Encrypt(ctx.keys.publicKey, p1);
                    auto ct2 = ctx.cc_P->Encrypt(ctx.keys.publicKey, p2);
                    auto tb0 = Clock::now();
                    auto ct_block = ctx.cc_P->EvalMultNoRelin(ct1, ct2);
                    ct_block = DPad_Relin(ctx, ct_block, dpad_keys, r, r_ext);
                    ct_block = ctx.cc_P->Rescale(ct_block);
                    auto tb1 = Clock::now();
                    sum_block += elapsed_ms(tb0, tb1);
                }
                block_means.push_back(sum_block / ITERATIONS_PER_RUN);
            }
            hmult_dpad = median(block_means);
        }
        (void)profiler.stop_and_get_gb();
        release_contexts<DCRTModule>();
    }

    // ---------------- per-test report ----------------
    report_row("key    meas (MB)", cell(guard.run_rlwe, key_rlwe_meas * 1024.0, 1),
               cell(guard.run_modhe, key_modhe_meas * 1024.0, 1),
               cell(guard.run_dpad, key_dpad_meas * 1024.0, 1));
    report_row("time   hmult+rescale (s)",
               cell(guard.run_rlwe, hmult_rlwe / 1000.0, 4),
               cell(guard.run_modhe, hmult_modhe / 1000.0, 4),
               cell(guard.run_dpad, hmult_dpad / 1000.0, 4));

    std::string speedup = "N/A";
    if (guard.run_modhe && guard.run_dpad && hmult_dpad > 0)
        speedup = fmt(hmult_modhe / hmult_dpad, 2) + "x";
    report_note("speedup DPad vs ModHE", speedup);
    std::string ratio = "N/A";
    if (guard.run_rlwe && guard.run_dpad && hmult_rlwe > 0)
        ratio = fmt(hmult_dpad / hmult_rlwe * 100.0, 0) + "%";
    report_note("ratio DPad vs RNS-CKKS", ratio);

    const double speedup_val =
        (guard.run_modhe && guard.run_dpad && hmult_dpad > 0) ? hmult_modhe / hmult_dpad : -1.0;
    const double ratio_val =
        (guard.run_rlwe && guard.run_dpad) ? hmult_dpad / hmult_rlwe * 100.0 : -1.0;
    const double key_ratio_val =
        (guard.run_rlwe && guard.run_dpad && key_rlwe_meas > 0) ? key_dpad_meas / key_rlwe_meas * 100.0 : -1.0;

    // Times in seconds, key sizes in MB, ratios in percent (Table 6 and Table 7).
    csv << name << "," << L << "," << N << "," << N_rlwe << "," << r << "," << r_ext << "," << mu << ","
        << fmt(csv_field(guard.run_rlwe, hmult_rlwe, 1.0 / 1000.0), 4) << ","
        << fmt(csv_field(guard.run_modhe, hmult_modhe, 1.0 / 1000.0), 4) << ","
        << fmt(csv_field(guard.run_dpad, hmult_dpad, 1.0 / 1000.0), 4) << ","
        << fmt(speedup_val, 3) << "," << fmt(ratio_val, 1) << ","
        << fmt(csv_field(guard.run_rlwe, key_rlwe_meas, 1024.0), 1) << ","
        << fmt(csv_field(guard.run_modhe, key_modhe_meas, 1024.0), 1) << ","
        << fmt(csv_field(guard.run_dpad, key_dpad_meas, 1024.0), 1) << ","
        << fmt(key_ratio_val, 1) << "\n";
    csv.flush();
}

int main(int argc, char** argv) {
    const int flag_status = parse_loop_flags(argc, argv);
    if (flag_status != 0) return flag_status == 2 ? 0 : 1;
    std::ofstream csv("../results/table5_results.csv");
    csv << "Set,L,n,n_RLWE,r,r_ext,mu,"
           "Time_RNS_s,Time_Mod_s,Time_DPad_s,"
           "Speedup_DPad_vs_ModHE,Ratio_DPad_vs_RNS_pct,"
           "Key_RNS_MB,Key_Mod_MB,Key_DPad_MB,Key_Ratio_pct\n";
    g_initial_ram_gb = get_available_ram_gb();

    std::cout << "Paper Table 5: same-depth sets (Table 6 time, Table 7 key size)\n";
    std::cout << "median of " << RUNS_PER_TEST << " runs x " << ITERATIONS_PER_RUN
              << " iterations\n";
    std::cout << "RAM guard: run only if estimated peak < available - "
              << fmt(RAM_SAFETY_BUFFER_GB, 1) << " GB  (available: "
              << fmt(g_initial_ram_gb, 1) << " GB)\n";

    // Paper Table 5. mu reconstructed as ceil((L+1)/(K+1)) with K the 55-bit
    // prime count in log2 P_hat (Set II: 6, Set III: 4, Set V: 13, Set VI: 9); the 60-bit
    // leading prime is counted separately, as in the Table-3 mu vector. Here K
    // varies at fixed L, so mu no longer tracks r. Sets I and IV are the plain
    // RNS-CKKS baseline (r = 1) and are covered by the baseline column.
    run_eval("II",  TABLE5_DEPTH_SMALL, 16384, 2, 3, 3, csv); // N = 2^15, n = 2^14
    run_eval("III", TABLE5_DEPTH_SMALL,  8192, 4, 5, 4, csv); // N = 2^15, n = 2^13
    run_eval("V",   TABLE5_DEPTH_LARGE, 32768, 2, 3, 3, csv); // N = 2^16, n = 2^15
    run_eval("VI",  TABLE5_DEPTH_LARGE, 16384, 4, 5, 5, csv); // N = 2^16, n = 2^14

    return 0;
}
