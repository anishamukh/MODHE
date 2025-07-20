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

#ifndef LBCRYPTO_CRYPTO_CKKSMOD_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_CKKSMOD_LEVELEDSHE_H

#include "schemebase/base-leveledshe.h"

#include <memory>
#include <string>
#include <map>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class LeveledSHECKKSMod : public LeveledSHEBase<DCRTModule> {
public:
    virtual ~LeveledSHECKKSMod() {}

    void EvalAddInPlace(Ciphertext<DCRTModule>& ciphertext1, ConstCiphertext<DCRTModule> ciphertext2) const override;

    void EvalSubInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                           ConstCiphertext<DCRTModule> ciphertext2) const override;

    Ciphertext<DCRTModule> EvalMult(ConstCiphertext<DCRTModule> ciphertext1,
                                    ConstCiphertext<DCRTModule> ciphertext2) const override;

    Ciphertext<DCRTModule> EvalMult(ConstCiphertext<DCRTModule> ciphertext1, ConstCiphertext<DCRTModule> ciphertext2,
                                    const EvalKey<DCRTModule> evalKey) const override {
        OPENFHE_THROW("EvalMult with evalKey not supported for this scheme");  // Needs more than one evalKey
    }

    Ciphertext<DCRTModule> EvalMultCore(ConstCiphertext<DCRTModule> ciphertext1,
                                        ConstCiphertext<DCRTModule> ciphertext2) const override;

    void EvalMultCoreInPlace(Ciphertext<DCRTModule>& ciphertext, double operand) const;

    EvalKey<DCRTModule> EvalMultKeyGen(const PrivateKey<DCRTModule> privateKey) const {
        OPENFHE_THROW(
            "EvalMultKeyGen not supported for this scheme use EvalMultModKeyGen instead");  // Needs more than one evalKey
    }

    std::vector<EvalKey<DCRTModule>> EvalMultModKeyGen(const PrivateKey<DCRTModule> privateKey) const override;

    EvalKey<DCRTModule> EvalRankRedKeyGen(const PrivateKey<DCRTModule> privateKey, PrivateKey<DCRTModule>& reducedKey, usint newRank) const override;

    Ciphertext<DCRTModule> EvalRankReduce(ConstCiphertext<DCRTModule> ciphertext, EvalKey<DCRTModule> reduceKey) const override;

    void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTModule>& ciphertext1, Ciphertext<DCRTModule>& ciphertext2) const;

    void AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                          Ciphertext<DCRTModule>& ciphertext2) const override;

    Ciphertext<DCRTModule> ModReduce(ConstCiphertext<DCRTModule> ciphertext, size_t levels) const override;

    void ModReduceInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const override;

    void ModReduceInternalInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const override;

    void LevelReduceInternalInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const override;

    std::vector<DCRTModule::Integer> GetElementForEvalMult(ConstCiphertext<DCRTModule> ciphertext,
                                                           double operand) const;

    void AdjustLevelsInPlace(Ciphertext<DCRTModule>& ciphertext1, Ciphertext<DCRTModule>& ciphertext2) const override;

    void AdjustForAddOrSubInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                  Ciphertext<DCRTModule>& ciphertext2) const override;

    void AdjustForMultInPlace(Ciphertext<DCRTModule>& ciphertext1, Ciphertext<DCRTModule>& ciphertext2) const override;

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<LeveledSHEBase<DCRTModule>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<LeveledSHEBase<DCRTModule>>(this));
    }

    std::string SerializedObjectName() const {
        return "LeveledSHECKKSMod";
    }
};

}  // namespace lbcrypto

#endif
