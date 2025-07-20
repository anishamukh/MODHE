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
CKKS implementation. If NOISE_FLOODING_DECRYPT is set, we flood the decryption bits with noise.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/ckksmod/ckksmod-cryptoparameters.h"
#include "scheme/ckksmod/ckksmod-pke.h"

namespace lbcrypto {

// makeSparse is not used by this scheme
KeyPair<DCRTModule> PKECKKSMOD::KeyGenInternal(CryptoContext<DCRTModule> cc, bool makeSparse) const {
    KeyPair<DCRTModule> keyPair(std::make_shared<PublicKeyImpl<DCRTModule>>(cc),
                                std::make_shared<PrivateKeyImpl<DCRTModule>>(cc));

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(cc->GetCryptoParameters());

    const std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
    const std::shared_ptr<ParmType> paramsPK      = cryptoParams->GetParamsPK();
    if (!paramsPK) {
        OPENFHE_THROW("PrecomputeCRTTables() must be called before using precomputed params.");
    }

    const auto ns      = cryptoParams->GetNoiseScale();
    const DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DugType dug;
    TugType tug;

    // Private Key Generation

    DCRTModule s;
    switch (cryptoParams->GetSecretKeyDist()) {
        case GAUSSIAN:
            s = DCRTModule(dgg, paramsPK, Format::EVALUATION, cryptoParams->GetModuleRank());
            break;
        case UNIFORM_TERNARY:
            s = DCRTModule(tug, paramsPK, Format::EVALUATION, 0, cryptoParams->GetModuleRank());
            break;
        case SPARSE_TERNARY:
            // https://github.com/openfheorg/openfhe-development/issues/311
            s = DCRTModule(tug, paramsPK, Format::EVALUATION, 192, cryptoParams->GetModuleRank());
            break;
        default:
            break;
    }

    // Public Key Generation

    DCRTModule A(dug, paramsPK, Format::EVALUATION, cryptoParams->GetModuleRank(), cryptoParams->GetModuleRank());
    DCRTModule e(dgg, paramsPK, Format::EVALUATION, cryptoParams->GetModuleRank());
    DCRTModule b(ns * e - A * s);

    keyPair.secretKey->SetPrivateElement(std::move(s));
    keyPair.publicKey->SetPublicElements(std::vector<DCRTModule>{std::move(b), std::move(A)});
    keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());

    return keyPair;
}

Ciphertext<DCRTModule> PKECKKSMOD::Encrypt(DCRTModule plaintext, const PrivateKey<DCRTModule> privateKey) const {
    OPENFHE_THROW("Encrypt not supported for modules");
}

Ciphertext<DCRTModule> PKECKKSMOD::Encrypt(DCRTModule plaintext, const PublicKey<DCRTModule> publicKey) const {
    Ciphertext<DCRTModule> ciphertext(std::make_shared<CiphertextImpl<DCRTModule>>(publicKey));

    const std::shared_ptr<ParmType> ptxtParams  = plaintext.GetParams();
    std::shared_ptr<std::vector<DCRTModule>> ba = EncryptZeroCore(publicKey, ptxtParams);

    plaintext.SetFormat(EVALUATION);

    (*ba)[0] += plaintext;

    ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
    ciphertext->SetNoiseScaleDeg(1);

    return ciphertext;
}

std::shared_ptr<std::vector<DCRTModule>> PKECKKSMOD::EncryptZeroCore(const PrivateKey<DCRTModule> privateKey,
                                                                     const std::shared_ptr<ParmType> params) const {
    OPENFHE_THROW("EncryptZeroCore not supported for modules");
}

std::shared_ptr<std::vector<DCRTModule>> PKECKKSMOD::EncryptZeroCore(const PublicKey<DCRTModule> publicKey,
                                                                     const std::shared_ptr<ParmType> params) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(publicKey->GetCryptoParameters());

    const std::vector<DCRTModule>& pk = publicKey->GetPublicElements();
    const auto ns                     = cryptoParams->GetNoiseScale();
    const DggType& dgg                = cryptoParams->GetDiscreteGaussianGenerator();

    TugType tug;

    const std::shared_ptr<ParmType> elementParams = (params == nullptr) ? cryptoParams->GetElementParams() : params;
    // TODO (dsuponit): "tug" must be assigned with TernaryUniformGenerator. Otherwise the DCRTModule constructor crashes.
    // check other files if "tug" is properly assigned
    // if (cryptoParams->GetSecretKeyDist() != GAUSSIAN) {
    //    OPENFHE_THROW("TugType tug must be assigned");
    //}
    DCRTModule v = cryptoParams->GetSecretKeyDist() == GAUSSIAN ?
                       DCRTModule(dgg, elementParams, Format::EVALUATION, 1, cryptoParams->GetModuleRank()) :
                       DCRTModule(tug, elementParams, Format::EVALUATION, 0, 1, cryptoParams->GetModuleRank());

    // noise generation with the discrete gaussian generator dgg
    DCRTModule e0(dgg, elementParams, Format::EVALUATION, 1);
    DCRTModule e1(dgg, elementParams, Format::EVALUATION, 1, cryptoParams->GetModuleRank());

    uint32_t sizeQ  = pk[0].GetParams()->GetParams().size();
    uint32_t sizeQl = elementParams->GetParams().size();

    DCRTModule c0, c1;
    if (sizeQl != sizeQ) {
        // Clone public keys because we need to drop towers.
        DCRTModule p0 = pk[0].Clone();
        DCRTModule p1 = pk[1].Clone();

        uint32_t diffQl = sizeQ - sizeQl;
        p0.DropLastElements(diffQl);
        p1.DropLastElements(diffQl);

        c0 = v * p0 + ns * e0;
        c1 = v * p1 + ns * e1;
    }
    else {
        // Use public keys as they are
        const DCRTModule& p0 = pk[0];
        const DCRTModule& p1 = pk[1];

        c0 = v * p0 + ns * e0;
        c1 = v * p1 + ns * e1;
    }

    return std::make_shared<std::vector<DCRTModule>>(std::initializer_list<DCRTModule>({std::move(c0), std::move(c1)}));
}

DecryptResult PKECKKSMOD::Decrypt(ConstCiphertext<DCRTModule> ciphertext, const PrivateKey<DCRTModule> privateKey,
                                  NativePoly* plaintext) const {
    OPENFHE_THROW("Decrypt not supported for modules");
}

DecryptResult PKECKKSMOD::Decrypt(ConstCiphertext<DCRTModule> ciphertext, const PrivateKey<DCRTModule> privateKey,
                                  Poly* plaintext) const {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSMod>(ciphertext->GetCryptoParameters());
    const std::vector<DCRTModule>& cv = ciphertext->GetElements();
    DCRTModule b                      = DecryptCore(cv, privateKey);
    if (cryptoParams->GetDecryptionNoiseMode() == NOISE_FLOODING_DECRYPT &&
        cryptoParams->GetExecutionMode() == EXEC_EVALUATION) {
        auto dgg = cryptoParams->GetFloodingDiscreteGaussianGenerator();
        DCRTModule noise(dgg, cv[0].GetParams(), Format::EVALUATION, cryptoParams->GetModuleRank());
        b += noise;
    }

    b.SetFormat(Format::COEFFICIENT);
    const size_t sizeQl = b.GetParams()->GetParams().size();

    if (sizeQl == 0)
        OPENFHE_THROW("Decryption failure: No towers left; consider increasing the depth.");

    if (sizeQl == 1) {
        *plaintext = Poly(b.GetDCRTPolyAt(0).GetElementAtIndex(0), Format::COEFFICIENT);
    }
    else {
        *plaintext = b.GetDCRTPolyAt(0).CRTInterpolate();
    }

    return DecryptResult(plaintext->GetLength());
}

DCRTModule PKECKKSMOD::DecryptCore(const std::vector<DCRTModule>& cv, const PrivateKey<DCRTModule> privateKey) const {
    if (cv.size() != 2) {
        OPENFHE_THROW("Decryption of ciphertext with more than 2 elements is not supported");
    }
    DCRTModule s = privateKey->GetPrivateElement();

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    return cv[0] + cv[1] * scopy;
}

}  // namespace lbcrypto
