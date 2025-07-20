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

/**
 * Hybrid key switching implementation. See
 * Appendix of https://eprint.iacr.org/2021/204 for details.
 */
#define PROFILE

#include "keyswitch/keyswitch-mod.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "key/evalkeyrelin.h"
#include "scheme/ckksmod/ckksmod-cryptoparameters.h"
#include "ciphertext.h"

namespace lbcrypto {

EvalKey<DCRTModule> KeySwitchMod::KeySwitchGenInternal(const PrivateKey<DCRTModule> oldKey,
                                                       const PrivateKey<DCRTModule> newKey) const {
    return KeySwitchMod::KeySwitchGenInternal(oldKey, newKey, nullptr);
}

EvalKey<DCRTModule> KeySwitchMod::KeySwitchGenInternal(const PrivateKey<DCRTModule> oldKey,
                                                       const PrivateKey<DCRTModule> newKey,
                                                       const EvalKey<DCRTModule> ekPrev) const {
    EvalKeyRelin<DCRTModule> ek(std::make_shared<EvalKeyRelinImpl<DCRTModule>>(newKey->GetCryptoContext()));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(newKey->GetCryptoParameters());

    const std::shared_ptr<ParmType> paramsQ  = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsQP = cryptoParams->GetParamsQP();

    size_t sizeQ  = paramsQ->GetParams().size();
    size_t sizeQP = paramsQP->GetParams().size();

    DCRTModule sOld = oldKey->GetPrivateElement();
    DCRTModule sNew = newKey->GetPrivateElement().Clone();

    // skNew is currently in basis Q. This extends it to basis QP.
    sNew.SetFormat(Format::COEFFICIENT);

    DCRTModule sNewExt(paramsQP, Format::COEFFICIENT, true, sNew.GetModuleRows());

    // The part with basis Q
    for (size_t row = 0; row < sNew.GetModuleRows(); row++) {
        for (size_t i = 0; i < sizeQ; i++) {
            sNewExt.SetElementAtIndex(row, 0, i, sNew.GetElementAtIndex(row, 0, i));
        }
    }

    // The part with basis P
    for (size_t row = 0; row < sNew.GetModuleRows(); row++) {
        for (size_t j = sizeQ; j < sizeQP; j++) {
            const NativeInteger& pj    = paramsQP->GetParams()[j]->GetModulus();
            const NativeInteger& rootj = paramsQP->GetParams()[j]->GetRootOfUnity();
            auto sNew0                 = sNew.GetElementAtIndex(row, 0, 0);
            sNew0.SwitchModulus(pj, rootj, 0, 0);
            sNewExt.SetElementAtIndex(row, 0, j, std::move(sNew0));
        }
    }

    sNewExt.SetFormat(Format::EVALUATION);

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;

    size_t numPartQ = cryptoParams->GetNumPartQ();

    std::vector<DCRTModule> Av(numPartQ);
    std::vector<DCRTModule> bv(numPartQ);

    std::vector<NativeInteger> PModq = cryptoParams->GetPModq();
    size_t numPerPartQ               = cryptoParams->GetNumPerPartQ();

    for (size_t part = 0; part < numPartQ; ++part) {
        DCRTModule A = (ekPrev == nullptr) ? DCRTModule(dug, paramsQP, Format::EVALUATION, sOld.GetModuleRows(),
                                                        sNew.GetModuleRows()) :  // single-key HE
                                             ekPrev->GetAVector()[part];                           // threshold HE
        DCRTModule e(dgg, paramsQP, Format::EVALUATION, sOld.GetModuleRows());
        DCRTModule b(paramsQP, Format::EVALUATION, true, sOld.GetModuleRows());

        // starting and ending position of current part
        size_t startPartIdx = numPerPartQ * part;
        size_t endPartIdx   = (sizeQ > (startPartIdx + numPerPartQ)) ? (startPartIdx + numPerPartQ) : sizeQ;

        for (size_t row = 0; row < sOld.GetModuleRows(); row++) {
            for (size_t i = 0; i < sizeQP; ++i) {
                auto Aji_sNew = A.GetElementAtIndex(row, 0, i) * sNewExt.GetElementAtIndex(0, 0, i);
                for (size_t j = 1; j < sNewExt.GetModuleRows(); j++) {
                    Aji_sNew += A.GetElementAtIndex(row, j, i) * sNewExt.GetElementAtIndex(j, 0, i);
                }
                auto ei = e.GetElementAtIndex(row, 0, i);

                if (i < startPartIdx || i >= endPartIdx) {
                    b.SetElementAtIndex(row, 0, i, -Aji_sNew + ns * ei);
                }
                else {
                    // P * sOld is only applied for the current part
                    auto sOldi = sOld.GetElementAtIndex(row, 0, i);
                    b.SetElementAtIndex(row, 0, i, -Aji_sNew + PModq[i] * sOldi + ns * ei);
                }
            }
        }

        Av[part] = A;
        bv[part] = b;
    }

    ek->SetAVector(std::move(Av));
    ek->SetBVector(std::move(bv));
    ek->SetKeyTag(newKey->GetKeyTag());
    return ek;
}

void KeySwitchMod::KeySwitchInPlace(Ciphertext<DCRTModule>& ciphertext, const EvalKey<DCRTModule> ek) const {
    std::vector<DCRTModule>& cv = ciphertext->GetElements();

    std::shared_ptr<std::vector<DCRTModule>> ba =
        (cv.size() == 2) ? KeySwitchCore(cv[1], ek) : KeySwitchCore(cv[2], ek);

    cv[0].SetFormat((*ba)[0].GetFormat());
    cv[0] += (*ba)[0];

    cv[1].SetFormat((*ba)[1].GetFormat());
    if (cv.size() > 2) {
        cv[1] += (*ba)[1];
    }
    else {
        cv[1] = (*ba)[1];
    }
    cv.resize(2);
}

std::shared_ptr<std::vector<DCRTModule>> KeySwitchMod::KeySwitchCore(const DCRTModule& a,
                                                                     const EvalKey<DCRTModule> evalKey) const {
    return EvalFastKeySwitchCore(EvalKeySwitchPrecomputeCore(a, evalKey->GetCryptoParameters()), evalKey,
                                 a.GetParams());
}

std::shared_ptr<std::vector<DCRTModule>> KeySwitchMod::EvalKeySwitchPrecomputeCore(
    const DCRTModule& c, std::shared_ptr<CryptoParametersBase<DCRTModule>> cryptoParamsBase) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(cryptoParamsBase);

    const std::shared_ptr<ParmType> paramsQl  = c.GetParams();
    const std::shared_ptr<ParmType> paramsP   = cryptoParams->GetParamsP();
    const std::shared_ptr<ParmType> paramsQlP = c.GetExtendedCRTBasis(paramsP);

    size_t sizeQl  = paramsQl->GetParams().size();
    size_t sizeP   = paramsP->GetParams().size();
    size_t sizeQlP = sizeQl + sizeP;

    uint32_t alpha = cryptoParams->GetNumPerPartQ();
    // The number of digits of the current ciphertext
    uint32_t numPartQl = ceil((static_cast<double>(sizeQl)) / alpha);
    if (numPartQl > cryptoParams->GetNumberOfQPartitions())
        numPartQl = cryptoParams->GetNumberOfQPartitions();

    std::vector<DCRTModule> partsCt(numPartQl);

    // Digit decomposition
    // Zero-padding and split
    for (uint32_t part = 0; part < numPartQl; part++) {
        if (part == numPartQl - 1) {
            auto paramsPartQ = cryptoParams->GetParamsPartQ(part);

            uint32_t sizePartQl = sizeQl - alpha * part;

            std::vector<NativeInteger> moduli(sizePartQl);
            std::vector<NativeInteger> roots(sizePartQl);

            for (uint32_t i = 0; i < sizePartQl; i++) {
                moduli[i] = paramsPartQ->GetParams()[i]->GetModulus();
                roots[i]  = paramsPartQ->GetParams()[i]->GetRootOfUnity();
            }

            auto params = DCRTModule::Params(paramsPartQ->GetCyclotomicOrder(), moduli, roots);

            partsCt[part] =
                DCRTModule(std::make_shared<ParmType>(params), Format::EVALUATION, true, 1, c.GetModuleCols());
        }
        else {
            partsCt[part] =
                DCRTModule(cryptoParams->GetParamsPartQ(part), Format::EVALUATION, true, 1, c.GetModuleCols());
        }

        usint sizePartQl   = partsCt[part].GetNumOfElements();
        usint startPartIdx = alpha * part;
        for (size_t col = 0; col < c.GetModuleCols(); col++) {
            for (uint32_t i = 0, idx = startPartIdx; i < sizePartQl; i++, idx++) {
                partsCt[part].SetElementAtIndex(0, col, i, c.GetElementAtIndex(0, col, idx));
            }
        }
    }

    std::vector<DCRTModule> partsCtCompl(numPartQl);
    std::vector<DCRTModule> partsCtExt(numPartQl);

    for (uint32_t part = 0; part < numPartQl; part++) {
        auto partCtClone = partsCt[part].Clone();
        partCtClone.SetFormat(Format::COEFFICIENT);

        uint32_t sizePartQl = partsCt[part].GetNumOfElements();
        partsCtCompl[part]  = partCtClone.ApproxSwitchCRTBasis(
            cryptoParams->GetParamsPartQ(part), cryptoParams->GetParamsComplPartQ(sizeQl - 1, part),
            cryptoParams->GetPartQlHatInvModq(part, sizePartQl - 1),
            cryptoParams->GetPartQlHatInvModqPrecon(part, sizePartQl - 1),
            cryptoParams->GetPartQlHatModp(sizeQl - 1, part),
            cryptoParams->GetmodComplPartqBarrettMu(sizeQl - 1, part));

        partsCtCompl[part].SetFormat(Format::EVALUATION);

        partsCtExt[part] = DCRTModule(paramsQlP, Format::EVALUATION, true, 1, c.GetModuleCols());

        for (size_t col = 0; col < c.GetModuleCols(); col++) {
            usint startPartIdx = alpha * part;
            usint endPartIdx   = startPartIdx + sizePartQl;
            for (usint i = 0; i < startPartIdx; i++) {
                partsCtExt[part].SetElementAtIndex(0, col, i, partsCtCompl[part].GetElementAtIndex(0, col, i));
            }
            for (usint i = startPartIdx, idx = 0; i < endPartIdx; i++, idx++) {
                partsCtExt[part].SetElementAtIndex(0, col, i, partsCt[part].GetElementAtIndex(0, col, idx));
            }
            for (usint i = endPartIdx; i < sizeQlP; ++i) {
                partsCtExt[part].SetElementAtIndex(0, col, i,
                                                   partsCtCompl[part].GetElementAtIndex(0, col, i - sizePartQl));
            }
        }
    }

    return std::make_shared<std::vector<DCRTModule>>(std::move(partsCtExt));
}

std::shared_ptr<std::vector<DCRTModule>> KeySwitchMod::EvalFastKeySwitchCore(
    const std::shared_ptr<std::vector<DCRTModule>> digits, const EvalKey<DCRTModule> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(evalKey->GetCryptoParameters());

    std::shared_ptr<std::vector<DCRTModule>> cTilda = EvalFastKeySwitchCoreExt(digits, evalKey, paramsQl);

    PlaintextModulus t = (cryptoParams->GetNoiseScale() == 1) ? 0 : cryptoParams->GetPlaintextModulus();

    DCRTModule ct0 = (*cTilda)[0].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                                cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                                cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                                cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                                cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    DCRTModule ct1 = (*cTilda)[1].ApproxModDown(paramsQl, cryptoParams->GetParamsP(), cryptoParams->GetPInvModq(),
                                                cryptoParams->GetPInvModqPrecon(), cryptoParams->GetPHatInvModp(),
                                                cryptoParams->GetPHatInvModpPrecon(), cryptoParams->GetPHatModq(),
                                                cryptoParams->GetModqBarrettMu(), cryptoParams->GettInvModp(),
                                                cryptoParams->GettInvModpPrecon(), t, cryptoParams->GettModqPrecon());

    return std::make_shared<std::vector<DCRTModule>>(std::initializer_list<DCRTModule>{std::move(ct0), std::move(ct1)});
}

std::shared_ptr<std::vector<DCRTModule>> KeySwitchMod::EvalFastKeySwitchCoreExt(
    const std::shared_ptr<std::vector<DCRTModule>> digits, const EvalKey<DCRTModule> evalKey,
    const std::shared_ptr<ParmType> paramsQl) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(evalKey->GetCryptoParameters());
    const std::vector<DCRTModule>& bv = evalKey->GetBVector();
    const std::vector<DCRTModule>& Av = evalKey->GetAVector();

    const std::shared_ptr<ParmType> paramsP   = cryptoParams->GetParamsP();
    const std::shared_ptr<ParmType> paramsQlP = (*digits)[0].GetParams();

    size_t sizeQl  = paramsQl->GetParams().size();
    size_t sizeQlP = paramsQlP->GetParams().size();
    size_t sizeQ   = cryptoParams->GetElementParams()->GetParams().size();

    DCRTModule cTilda0(paramsQlP, Format::EVALUATION, true, 1);
    DCRTModule cTilda1(paramsQlP, Format::EVALUATION, true, 1, Av[0].GetModuleCols());

    for (uint32_t j = 0; j < digits->size(); j++) {
        const DCRTModule& cj = (*digits)[j];
        const DCRTModule& bj = bv[j];
        const DCRTModule& Aj = Av[j];

        for (size_t col = 0; col < cj.GetModuleCols(); col++) {
            for (usint i = 0; i < sizeQl; i++) {
                const auto& cji = cj.GetElementAtIndex(0, col, i);
                const auto& bji = bj.GetElementAtIndex(col, 0, i);

                cTilda0.SetElementAtIndex(0, 0, i, cTilda0.GetElementAtIndex(0, 0, i) + cji * bji);
            }
            for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
                const auto& cji = cj.GetElementAtIndex(0, col, i);
                const auto& bji = bj.GetElementAtIndex(col, 0, idx);

                cTilda0.SetElementAtIndex(0, 0, i, cTilda0.GetElementAtIndex(0, 0, i) + cji * bji);
            }
        }
        for (size_t col = 0; col < cTilda1.GetModuleCols(); col++) {
            for (usint i = 0; i < sizeQl; i++) {
                auto cji_Aji = cj.GetElementAtIndex(0, 0, i) * Aj.GetElementAtIndex(0, col, i);
                for (size_t k = 1; k < cj.GetModuleCols(); k++) {
                    cji_Aji += cj.GetElementAtIndex(0, k, i) * Aj.GetElementAtIndex(k, col, i);
                }

                cTilda1.SetElementAtIndex(0, col, i, cTilda1.GetElementAtIndex(0, col, i) + cji_Aji);
            }
            for (usint i = sizeQl, idx = sizeQ; i < sizeQlP; i++, idx++) {
                auto cji_Aji = cj.GetElementAtIndex(0, 0, i) * Aj.GetElementAtIndex(0, col, idx);
                for (size_t k = 1; k < cj.GetModuleCols(); k++) {
                    cji_Aji += cj.GetElementAtIndex(0, k, i) * Aj.GetElementAtIndex(k, col, idx);
                }

                cTilda1.SetElementAtIndex(0, col, i, cTilda1.GetElementAtIndex(0, col, i) + cji_Aji);
            }
        }
    }

    return std::make_shared<std::vector<DCRTModule>>(
        std::initializer_list<DCRTModule>{std::move(cTilda0), std::move(cTilda1)});
}

}  // namespace lbcrypto
