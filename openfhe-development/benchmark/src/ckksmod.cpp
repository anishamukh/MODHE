//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Simple examples for ModHE
 */

#define PROFILE

#include <chrono>
#include <functional>
#include <optional>

#include "openfhe.h"

using namespace lbcrypto;

using CT   = Ciphertext<DCRTModule>;
using CC   = CryptoContext<DCRTModule>;
using Keys = KeyPair<DCRTModule>;

struct BenchResult {
    long millis;
    long iterations;

    friend std::ostream& operator<<(std::ostream& os, const BenchResult& bench) {
        return os << bench.iterations << "," << bench.millis;
    }
};

BenchResult benchmark(CC& cc, Keys& keys, Plaintext ptxt1, CT& c1, CT& c2, std::optional<CT> c3,
                      std::function<void(CC, Keys, Plaintext, CT, CT, std::optional<CT>)> bench) {
    uint32_t iterations = 10;
    while (true) {
        auto started = std::chrono::high_resolution_clock::now();
        for (uint32_t i = 0; i < iterations; i++) {
            bench(cc, keys, ptxt1, c1, c2, c3);
        }
        auto done   = std::chrono::high_resolution_clock::now();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(done - started).count();
        if (millis >= 100)
            return {millis, iterations};
        iterations *= 2;
    }
}

int runRankRed() {
    std::cout << "operation,ringDim,rank,scaleModSize,multDepth,newRank,iterations,ms" << std::endl;
    uint32_t scaleModSize = 50;

    for (uint32_t moduleRank = 2; moduleRank <= 32; moduleRank *= 2) {
        for (uint32_t newRank = 1; newRank < moduleRank; newRank++) {
            uint32_t ringDim   = 1024;
            uint32_t multDepth = 2;
            CCParams<CryptoContextCKKSMod> parameters;
            parameters.SetRingDim(ringDim);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetMultiplicativeDepth(multDepth);
            parameters.SetScalingModSize(scaleModSize);
            parameters.SetBatchSize(8);
            parameters.SetModuleRank(moduleRank);
            parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);

            CryptoContext<DCRTModule> cc = GenCryptoContext(parameters);

            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);
            cc->Enable(KEYSWITCH);

            auto keys = cc->KeyGen();

            std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};

            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);

            auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

            PrivateKey<DCRTModule> reducedKey;

            auto rankredKey = cc->EvalRankRedKeyGen(keys.secretKey, reducedKey, newRank);
            auto cRed       = cc->EvalRankReduce(c1, rankredKey);

            std::cout << "RankRedKeyGen," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth
                      << "," << newRank << ","
                      << benchmark(cc, keys, ptxt1, c1, c1, std::nullopt,
                                   [newRank](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) {
                                       PrivateKey<DCRTModule> reducedKey;
                                       cc->EvalRankRedKeyGen(keys.secretKey, reducedKey, newRank);
                                   })
                      << std::endl;

            std::cout << "RankRed," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth << ","
                      << newRank << ","
                      << benchmark(cc, keys, ptxt1, c1, c1, std::nullopt,
                                   [rankredKey](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) {
                                       cc->EvalRankReduce(c1, rankredKey);
                                   })
                      << std::endl;
        }
    }

    return 0;
}

int runBaseOperations() {
    std::cout << "operation,ringDim,rank,scaleModSize,multDepth,iterations,ms" << std::endl;
    uint32_t scaleModSize = 50;

    for (uint32_t multDepth = 2; multDepth <= 2; multDepth++) {
        for (uint32_t ringDim = 1024; ringDim <= 1024 * 128; ringDim *= 2) {
            for (uint32_t moduleRank = 1; ringDim * moduleRank <= 1024 * 128; moduleRank *= 2) {
                CCParams<CryptoContextCKKSMod> parameters;
                parameters.SetRingDim(ringDim);
                parameters.SetSecurityLevel(HEStd_NotSet);
                parameters.SetMultiplicativeDepth(multDepth);
                parameters.SetScalingModSize(scaleModSize);
                parameters.SetBatchSize(8);
                parameters.SetModuleRank(moduleRank);
                parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);

                CryptoContext<DCRTModule> cc = GenCryptoContext(parameters);

                cc->Enable(PKE);
                cc->Enable(LEVELEDSHE);
                cc->Enable(KEYSWITCH);

                auto keys = cc->KeyGen();

                std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
                std::vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

                Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
                Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2);

                auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
                auto c2 = cc->Encrypt(keys.publicKey, ptxt2);

                std::cout << "KeyGen," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth << ","
                          << benchmark(
                                 cc, keys, ptxt1, c1, c2, std::nullopt,
                                 [](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) { cc->KeyGen(); })
                          << std::endl;
                std::cout << "Decrypt," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth
                          << ","
                          << benchmark(cc, keys, ptxt1, c1, c2, std::nullopt,
                                       [](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) {
                                           cc->Decrypt(keys.secretKey, c1, &pt);
                                       })
                          << std::endl;
                std::cout << "Encrypt," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth
                          << ","
                          << benchmark(cc, keys, ptxt1, c1, c2, std::nullopt,
                                       [](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) {
                                           cc->Encrypt(keys.publicKey, pt);
                                       })
                          << std::endl;

                std::cout << "EvalAdd," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth
                          << ","
                          << benchmark(
                                 cc, keys, ptxt1, c1, c2, std::nullopt,
                                 [](CC cc, Keys, Plaintext, CT c1, CT c2, std::optional<CT>) { cc->EvalAdd(c1, c2); })
                          << std::endl;

                std::cout << "EvalSub," << ringDim << "," << moduleRank << "," << scaleModSize << "," << multDepth
                          << ","
                          << benchmark(
                                 cc, keys, ptxt1, c1, c2, std::nullopt,
                                 [](CC cc, Keys, Plaintext, CT c1, CT c2, std::optional<CT>) { cc->EvalSub(c1, c2); })
                          << std::endl;

                std::cout << "EvalMultNoRelin," << ringDim << "," << moduleRank << "," << scaleModSize << ","
                          << multDepth << ","

                          << benchmark(cc, keys, ptxt1, c1, c2, std::nullopt,
                                       [](CC cc, Keys, Plaintext, CT c1, CT c2, std::optional<CT>) {
                                           cc->EvalMultNoRelin(c1, c2);
                                       })
                          << std::endl;

                if (ringDim * moduleRank <= 1024 * 32) {
                    cc->EvalMultModKeyGen(keys.secretKey);

                    std::cout << "EvalMultModKeyGen," << ringDim << "," << moduleRank << "," << scaleModSize << ","
                              << multDepth << ","
                              << benchmark(cc, keys, ptxt1, c1, c2, std::nullopt,
                                           [](CC cc, Keys keys, Plaintext pt, CT c1, CT, std::optional<CT>) {
                                               cc->EvalMultModKeyGen(keys.secretKey);
                                           })
                              << std::endl;

                    std::cout << "Relinearize," << ringDim << "," << moduleRank << "," << scaleModSize << ","
                              << multDepth << ","
                              << benchmark(
                                     cc, keys, ptxt1, c1, c2, cc->EvalMultNoRelin(c1, c2),
                                     [](CC cc, Keys, Plaintext, CT, CT, std::optional<CT> c3) { cc->Relinearize(*c3); })
                              << std::endl;
                }
            }
        }
    }

    return 0;
}

int main() {
    runBaseOperations();
    // runRankRed();
    return 0;
}