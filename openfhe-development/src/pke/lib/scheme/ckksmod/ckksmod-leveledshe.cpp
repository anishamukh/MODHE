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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#include "cryptocontext.h"

#include "math/hal/basicint.h"

#include "scheme/ckksmod/ckksmod-cryptoparameters.h"
#include "scheme/ckksmod/ckksmod-leveledshe.h"

#include "schemebase/base-scheme.h"

namespace lbcrypto {

void LeveledSHECKKSMod::EvalAddInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                       ConstCiphertext<DCRTModule> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalAddCoreInPlace(ciphertext1, ciphertext2);
    }
    else {
        auto c2 = ciphertext2->Clone();
        AdjustForAddOrSubInPlace(ciphertext1, c2);

        EvalAddCoreInPlace(ciphertext1, c2);
    }
}

void LeveledSHECKKSMod::EvalSubInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                       ConstCiphertext<DCRTModule> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        EvalSubCoreInPlace(ciphertext1, ciphertext2);
    }
    else {
        auto c2 = ciphertext2->Clone();
        AdjustForAddOrSubInPlace(ciphertext1, c2);

        EvalSubCoreInPlace(ciphertext1, c2);
    }
}

Ciphertext<DCRTModule> LeveledSHECKKSMod::EvalMult(ConstCiphertext<DCRTModule> ciphertext1,
                                                   ConstCiphertext<DCRTModule> ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == NORESCALE) {
        return EvalMultCore(ciphertext1, ciphertext2);
    }

    auto c1 = ciphertext1->Clone();
    auto c2 = ciphertext2->Clone();
    AdjustForMultInPlace(c1, c2);

    return EvalMultCore(c1, c2);
}

Ciphertext<DCRTModule> LeveledSHECKKSMod::EvalMultCore(ConstCiphertext<DCRTModule> ciphertext1,
                                                       ConstCiphertext<DCRTModule> ciphertext2) const {
    VerifyNumOfTowers(ciphertext1, ciphertext2);
    Ciphertext<DCRTModule> result = ciphertext1->CloneZero();

    std::vector<DCRTModule> cv1        = ciphertext1->GetElements();
    const std::vector<DCRTModule>& cv2 = ciphertext2->GetElements();

    if (cv1.size() != 2 || cv2.size() != 2) {
        OPENFHE_THROW("EvalMultCore: only possible for ciphertexts of size 2.");
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    std::vector<DCRTModule> cvMult(3);

    cvMult[0] = cv1[0] * cv2[0];
    cvMult[1] = cv1[1] * cv2[0] + cv1[0] * cv2[1];
    cvMult[2] = cv1[1].HadamardProduct(cv2[1]);
    if (cryptoParams->GetModuleRank() > 1) {
        cvMult.push_back(cv1[1].LowerTriangleProduct(cv2[1]) + cv2[1].LowerTriangleProduct(cv1[1]));
    }

    result->SetElements(std::move(cvMult));
    result->SetNoiseScaleDeg(ciphertext1->GetNoiseScaleDeg() + ciphertext2->GetNoiseScaleDeg());
    result->SetScalingFactor(ciphertext1->GetScalingFactor() * ciphertext2->GetScalingFactor());
    const auto plainMod = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();
    result->SetScalingFactorInt(
        ciphertext1->GetScalingFactorInt().ModMul(ciphertext2->GetScalingFactorInt(), plainMod));
    return result;
}

void LeveledSHECKKSMod::EvalMultCoreInPlace(Ciphertext<DCRTModule>& ciphertext, double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());

    std::vector<DCRTModule::Integer> factors = GetElementForEvalMult(ciphertext, operand);
    std::vector<DCRTModule>& cv              = ciphertext->GetElements();
    for (usint i = 0; i < cv.size(); ++i) {
        cv[i] = cv[i] * factors;
    }
    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() + 1);

    double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);
}

std::vector<EvalKey<DCRTModule>> LeveledSHECKKSMod::EvalMultModKeyGen(const PrivateKey<DCRTModule> privateKey) const {
    const auto cc           = privateKey->GetCryptoContext();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(cc->GetCryptoParameters());

    const DCRTModule& s = privateKey->GetPrivateElement();

    auto algo = cc->GetScheme();

    std::vector<EvalKey<DCRTModule>> evalKeyVec;
    evalKeyVec.reserve(2);

    PrivateKey<DCRTModule> privateKeyPower = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc);
    privateKeyPower->SetPrivateElement(std::move(s.HadamardProduct(s)));
    evalKeyVec.push_back(algo->KeySwitchGen(privateKeyPower, privateKey));

    if (cryptoParams->GetModuleRank() > 1) {
        privateKeyPower->SetPrivateElement(std::move(s.LowerTriangleProduct(s)));
        evalKeyVec.push_back(algo->KeySwitchGen(privateKeyPower, privateKey));
    }
    return evalKeyVec;
}

/////////////////////////////////////
// Mod Reduce
/////////////////////////////////////

EvalKey<DCRTModule> LeveledSHECKKSMod::EvalRankRedKeyGen(const PrivateKey<DCRTModule> privateKey,
                                                         PrivateKey<DCRTModule>& reducedKey, usint newRank) const {
    if (newRank < 1 || newRank >= privateKey->GetPrivateElement().GetModuleRows()) {
        OPENFHE_THROW("Invalid new rank for EvalRankRedKeyGen: " + std::to_string(newRank));
    }

    const auto cc           = privateKey->GetCryptoContext();
    const auto cryptoParams = privateKey->GetCryptoParameters();

    const DCRTModule& s = privateKey->GetPrivateElement();

    auto algo = cc->GetScheme();

    DCRTModule sRem;
    auto sRed = s.DropRows(s.GetModuleRows() - newRank, sRem);

    reducedKey = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc);
    reducedKey->SetPrivateElement(std::move(sRed));

    PrivateKey<DCRTModule> removedKey = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc);
    removedKey->SetPrivateElement(std::move(sRem));

    return algo->KeySwitchGen(removedKey, reducedKey);
}

Ciphertext<DCRTModule> LeveledSHECKKSMod::EvalRankReduce(ConstCiphertext<DCRTModule> ciphertext,
                                                         EvalKey<DCRTModule> reduceKey) const {
    if (ciphertext->GetElements()[1].GetModuleCols() !=
        reduceKey->GetAVector()[0].GetModuleRows() + reduceKey->GetAVector()[0].GetModuleCols()) {
        OPENFHE_THROW("EvalRankRedKeyGen reduceKey does not match ciphertext rank");
    }

    Ciphertext<DCRTModule> result = ciphertext->Clone();

    std::vector<DCRTModule>& cv = result->GetElements();
    for (auto& c : cv)
        c.SetFormat(Format::EVALUATION);

    auto algo = result->GetCryptoContext()->GetScheme();

    DCRTModule cRemoved;
    auto cReduced = cv[1].DropColumns(reduceKey->GetAVector()[0].GetModuleRows(), cRemoved);

    std::shared_ptr<std::vector<DCRTModule>> ab = algo->KeySwitchCore(cRemoved, reduceKey);
    cv[0] += (*ab)[0];
    cv[1] = cReduced + (*ab)[1];

    return result;
}

void LeveledSHECKKSMod::AdjustLevelsAndDepthInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                                    Ciphertext<DCRTModule>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());
    usint c1lvl             = ciphertext1->GetLevel();
    usint c2lvl             = ciphertext2->GetLevel();
    usint c1depth           = ciphertext1->GetNoiseScaleDeg();
    usint c2depth           = ciphertext2->GetNoiseScaleDeg();
    auto sizeQl1            = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2            = ciphertext2->GetElements()[0].GetNumOfElements();

    if (c1lvl < c2lvl) {
        if (c1depth == 2) {
            if (c2depth == 2) {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = ciphertext2->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                double q1   = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
                ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                if (c1lvl + 1 < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
                }
                ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
            }
            else {
                if (c1lvl + 1 == c2lvl) {
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                }
                else {
                    double scf1 = ciphertext1->GetScalingFactor();
                    double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - 1);
                    double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                    double q1   = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
                    EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    if (c1lvl + 2 < c2lvl) {
                        LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 2);
                    }
                    ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
                }
            }
        }
        else {
            if (c2depth == 2) {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = ciphertext2->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
                LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl);
                ciphertext1->SetScalingFactor(scf2);
            }
            else {
                double scf1 = ciphertext1->GetScalingFactor();
                double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - 1);
                double scf  = cryptoParams->GetScalingFactorReal(c1lvl);
                EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
                if (c1lvl + 1 < c2lvl) {
                    LevelReduceInternalInPlace(ciphertext1, c2lvl - c1lvl - 1);
                }
                ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
                ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
            }
        }
    }
    else if (c1lvl > c2lvl) {
        if (c2depth == 2) {
            if (c1depth == 2) {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = ciphertext1->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                double q2   = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
                ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                if (c2lvl + 1 < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
                }
                ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
            }
            else {
                if (c2lvl + 1 == c1lvl) {
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                }
                else {
                    double scf2 = ciphertext2->GetScalingFactor();
                    double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - 1);
                    double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                    double q2   = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
                    EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    if (c2lvl + 2 < c1lvl) {
                        LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 2);
                    }
                    ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                    ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
                }
            }
        }
        else {
            if (c1depth == 2) {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = ciphertext1->GetScalingFactor();
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
                LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl);
                ciphertext2->SetScalingFactor(scf1);
            }
            else {
                double scf2 = ciphertext2->GetScalingFactor();
                double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - 1);
                double scf  = cryptoParams->GetScalingFactorReal(c2lvl);
                EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
                if (c2lvl + 1 < c1lvl) {
                    LevelReduceInternalInPlace(ciphertext2, c1lvl - c2lvl - 1);
                }
                ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
                ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
            }
        }
    }
    else {
        if (c1depth < c2depth) {
            EvalMultCoreInPlace(ciphertext1, 1.0);
        }
        else if (c2depth < c1depth) {
            EvalMultCoreInPlace(ciphertext2, 1.0);
        }
    }
}

void LeveledSHECKKSMod::AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                                         Ciphertext<DCRTModule>& ciphertext2) const {
    AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);

    if (ciphertext1->GetNoiseScaleDeg() == 2) {
        ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
        ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
    }
}

Ciphertext<DCRTModule> LeveledSHECKKSMod::ModReduce(ConstCiphertext<DCRTModule> ciphertext, size_t levels) const {
    Ciphertext<DCRTModule> result = ciphertext->Clone();
    ModReduceInPlace(result, levels);
    return result;
}

void LeveledSHECKKSMod::ModReduceInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        ModReduceInternalInPlace(ciphertext, levels);
    }
}

void LeveledSHECKKSMod::ModReduceInternalInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());

    std::vector<DCRTModule>& cv = ciphertext->GetElements();

    size_t sizeQ  = cryptoParams->GetElementParams()->GetParams().size();
    size_t sizeQl = cv[0].GetNumOfElements();
    size_t diffQl = sizeQ - sizeQl;

    for (size_t l = 0; l < levels; ++l) {
        for (size_t i = 0; i < cv.size(); ++i) {
            cv[i].DropLastElementAndScale(cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
                                          cryptoParams->GetqlInvModq(diffQl + l));
        }
    }

    ciphertext->SetNoiseScaleDeg(ciphertext->GetNoiseScaleDeg() - levels);
    ciphertext->SetLevel(ciphertext->GetLevel() + levels);

    for (usint i = 0; i < levels; ++i) {
        double modReduceFactor = cryptoParams->GetModReduceFactor(sizeQl - 1 - i);
        ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() / modReduceFactor);
    }
}

void LeveledSHECKKSMod::LevelReduceInternalInPlace(Ciphertext<DCRTModule>& ciphertext, size_t levels) const {
    std::vector<DCRTModule>& elements = ciphertext->GetElements();
    for (auto& element : elements) {
        element.DropLastElements(levels);
    }
    ciphertext->SetLevel(ciphertext->GetLevel() + levels);
}

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
std::vector<DCRTModule::Integer> LeveledSHECKKSMod::GetElementForEvalMult(ConstCiphertext<DCRTModule> ciphertext,
                                                                          double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());

    uint32_t precision = 52;
    double powP        = std::pow(2, precision);

    // the idea is to break down real numbers
    // expressed as input_mantissa * 2^input_exponent
    // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
    // to preserve 52-bit precision of doubles
    // when converting to 128-bit numbers
    int32_t n1         = 0;
    int64_t scaled64   = std::llround(static_cast<double>(std::frexp(operand, &n1)) * powP);
    int32_t pCurrent   = cryptoParams->GetPlaintextModulus() - precision;
    int32_t pRemaining = pCurrent + n1;
    int128_t scaled128 = 0;

    if (pRemaining < 0) {
        scaled128 = scaled64 >> (-pRemaining);
    }
    else {
        int128_t ppRemaining = ((int128_t)1) << pRemaining;
        scaled128            = ppRemaining * scaled64;
    }

    const std::vector<DCRTModule>& cv = ciphertext->GetElements();
    uint32_t numTowers                = cv[0].GetNumOfElements();
    std::vector<DCRTModule::Integer> factors(numTowers);

    for (usint i = 0; i < numTowers; i++) {
        DCRTModule::Integer modulus = cv[0].GetElementAtIndex(0, 0, i).GetModulus();

        if (scaled128 < 0) {
            DCRTModule::Integer reducedUnsigned = static_cast<BasicInteger>(-scaled128);
            reducedUnsigned.ModEq(modulus);
            factors[i] = modulus - reducedUnsigned;
        }
        else {
            DCRTModule::Integer reducedUnsigned = static_cast<BasicInteger>(scaled128);
            reducedUnsigned.ModEq(modulus);
            factors[i] = reducedUnsigned;
        }
    }
    return factors;
}
#else  // NATIVEINT == 64
std::vector<DCRTModule::Integer> LeveledSHECKKSMod::GetElementForEvalMult(ConstCiphertext<DCRTModule> ciphertext,
                                                                          double operand) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());

    const std::vector<DCRTModule>& cv = ciphertext->GetElements();
    uint32_t numTowers                = cv[0].GetNumOfElements();
    std::vector<DCRTModule::Integer> moduli(numTowers);
    for (usint i = 0; i < numTowers; i++) {
        moduli[i] = cv[0].GetElementAtIndex(0, 0, i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());

    #if defined(HAVE_INT128)
    typedef int128_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = 125;
    #else
    typedef int64_t DoubleInteger;
    int32_t MAX_BITS_IN_WORD_LOCAL = LargeScalingFactorConstants::MAX_BITS_IN_WORD;
    #endif

    // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.

    // the logic below was added as the code crashes when linked with clang++ in the Debug mode and
    // with the following flags and res is ZERO:
    // -O2
    // -g
    // -fsanitize-trap=all
    // -fsanitize=alignment,return,returns-nonnull-attribute,vla-bound,unreachable,float-cast-overflow
    // -fsanitize=null
    // -gz=zlib
    // -fno-asynchronous-unwind-tables
    // -fno-optimize-sibling-calls
    // -fsplit-dwarf-inlining
    // -gsimple-template-names
    // -gsplit-dwarf
    int32_t logApprox = 0;
    const double res  = std::fabs(operand * scFactor);
    if (res > 0) {
        int32_t logSF    = static_cast<int32_t>(std::ceil(std::log2(res)));
        int32_t logValid = (logSF <= MAX_BITS_IN_WORD_LOCAL) ? logSF : MAX_BITS_IN_WORD_LOCAL;
        logApprox        = logSF - logValid;
    }
    double approxFactor = pow(2, logApprox);

    DoubleInteger large     = static_cast<DoubleInteger>(operand / approxFactor * scFactor + 0.5);
    DoubleInteger large_abs = (large < 0 ? -large : large);
    DoubleInteger bound     = (uint64_t)1 << 63;

    std::vector<DCRTModule::Integer> factors(numTowers);

    if (large_abs >= bound) {
        for (usint i = 0; i < numTowers; i++) {
            DoubleInteger reduced = large % moduli[i].ConvertToInt();

            factors[i] = (reduced < 0) ? static_cast<uint64_t>(reduced + moduli[i].ConvertToInt()) :
                                         static_cast<uint64_t>(reduced);
        }
    }
    else {
        int64_t scConstant = static_cast<int64_t>(large);
        for (usint i = 0; i < numTowers; i++) {
            int64_t reduced = scConstant % static_cast<int64_t>(moduli[i].ConvertToInt());

            factors[i] = (reduced < 0) ? reduced + moduli[i].ConvertToInt() : reduced;
        }
    }

    // Scale back up by approxFactor within the CRT multiplications.
    if (logApprox > 0) {
        int32_t logStep             = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                          logApprox :
                                          LargeScalingFactorConstants::MAX_LOG_STEP;
        DCRTModule::Integer intStep = uint64_t(1) << logStep;
        std::vector<DCRTModule::Integer> crtApprox(numTowers, intStep);
        logApprox -= logStep;

        while (logApprox > 0) {
            int32_t logStep             = (logApprox <= LargeScalingFactorConstants::MAX_LOG_STEP) ?
                                              logApprox :
                                              LargeScalingFactorConstants::MAX_LOG_STEP;
            DCRTModule::Integer intStep = uint64_t(1) << logStep;
            std::vector<DCRTModule::Integer> crtSF(numTowers, intStep);
            crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
            logApprox -= logStep;
        }
        factors = CKKSPackedEncoding::CRTMult(factors, crtApprox, moduli);
    }

    return factors;
}

#endif

void LeveledSHECKKSMod::AdjustLevelsInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                            Ciphertext<DCRTModule>& ciphertext2) const {
    auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
    auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();

    if (sizeQl1 < sizeQl2) {
        LevelReduceInternalInPlace(ciphertext2, sizeQl2 - sizeQl1);
    }
    else if (sizeQl1 > sizeQl2) {
        LevelReduceInternalInPlace(ciphertext1, sizeQl1 - sizeQl2);
    }
}

void LeveledSHECKKSMod::AdjustForAddOrSubInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                                 Ciphertext<DCRTModule>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, ciphertext2);

        double scFactor = cryptoParams->GetScalingFactorReal();

        // supported only for CKKS
        if (scFactor == 0.0)
            return;

        DCRTModule ptxt;
        uint32_t ptxtDepth = 0;
        uint32_t ctxtDepth = 0;
        usint sizeQl       = 0;
        uint32_t ptxtIndex = 0;

        // Get moduli chain to create CRT representation of powP
        std::vector<DCRTModule::Integer> moduli;

        if (ciphertext1->NumberCiphertextElements() == 1) {
            ptxt      = ciphertext1->GetElements()[0];
            ptxtDepth = ciphertext1->GetNoiseScaleDeg();
            ctxtDepth = ciphertext2->GetNoiseScaleDeg();
            sizeQl    = ciphertext2->GetElements()[0].GetNumOfElements();
            moduli.resize(sizeQl);
            for (usint i = 0; i < sizeQl; i++) {
                moduli[i] = ciphertext2->GetElements()[0].GetElementAtIndex(0, 0, i).GetModulus();
            }
            ptxtIndex = 1;
        }
        else if (ciphertext2->NumberCiphertextElements() == 1) {
            ptxt      = ciphertext2->GetElements()[0];
            ptxtDepth = ciphertext2->GetNoiseScaleDeg();
            ctxtDepth = ciphertext1->GetNoiseScaleDeg();
            sizeQl    = ciphertext1->GetElements()[0].GetNumOfElements();
            moduli.resize(sizeQl);
            for (usint i = 0; i < sizeQl; i++) {
                moduli[i] = ciphertext1->GetElements()[0].GetElementAtIndex(0, 0, i).GetModulus();
            }
            ptxtIndex = 2;
        }
        else
            return;

        // Bring to same depth if not already same
        if (ptxtDepth < ctxtDepth) {
            // Find out how many levels to scale plaintext up.
            size_t diffDepth = ctxtDepth - ptxtDepth;

            DCRTModule::Integer intSF = static_cast<NativeInteger::Integer>(scFactor + 0.5);
            std::vector<DCRTModule::Integer> crtSF(sizeQl, intSF);
            auto crtPowSF = crtSF;
            for (usint j = 0; j < diffDepth - 1; j++) {
                crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
            }

            if (ptxtIndex == 1) {
                ciphertext1->SetElements(std::vector<DCRTModule>{ptxt.Times(crtPowSF)});
                ciphertext1->SetNoiseScaleDeg(ctxtDepth);
            }
            else {
                ciphertext2->SetElements(std::vector<DCRTModule>{ptxt.Times(crtPowSF)});
                ciphertext2->SetNoiseScaleDeg(ctxtDepth);
            }
        }
        else if (ptxtDepth > ctxtDepth) {
            OPENFHE_THROW("plaintext cannot be encoded at a larger depth than that of the ciphertext.");
        }
    }
    else if (cryptoParams->GetScalingTechnique() != NORESCALE) {
        AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    }
}

void LeveledSHECKKSMod::AdjustForMultInPlace(Ciphertext<DCRTModule>& ciphertext1,
                                             Ciphertext<DCRTModule>& ciphertext2) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext1->GetCryptoParameters());

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        AdjustLevelsInPlace(ciphertext1, ciphertext2);
    }
    else if (cryptoParams->GetScalingTechnique() != NORESCALE) {
        AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
        if (ciphertext1->GetNoiseScaleDeg() == 2) {
            ModReduceInternalInPlace(ciphertext1, BASE_NUM_LEVELS_TO_DROP);
            ModReduceInternalInPlace(ciphertext2, BASE_NUM_LEVELS_TO_DROP);
        }
    }
}

}  // namespace lbcrypto
