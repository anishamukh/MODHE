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
  Parameter class to generate CKKSMod crypto context
 */

#ifndef __GEN_CRYPTOCONTEXT_CKKSMOD_PARAMS_H__
#define __GEN_CRYPTOCONTEXT_CKKSMOD_PARAMS_H__

#include "scheme/gen-cryptocontext-params.h"

#include <string>
#include <vector>

namespace lbcrypto {

class CryptoContextCKKSMod;

// every CCParams class should include the following forward declaration as there is
// no general CCParams class template. This way we may create scheme specific classes
// derived from Params or have them completely independent.
template <typename T>
class CCParams;
//====================================================================================================================
template <>
class CCParams<CryptoContextCKKSMod> : public Params {
public:
    CCParams() : Params(CKKSMOD_SCHEME) {}
    explicit CCParams(const std::vector<std::string>& vals) : Params(vals) {}
    CCParams(const CCParams& obj) = default;
    CCParams(CCParams&& obj)      = default;
    ~CCParams()                   = default;

    //================================================================================================================
    // DISABLE FUNCTIONS that are not applicable to CKKSMod
    //================================================================================================================
    void SetPlaintextModulus(PlaintextModulus ptModulus0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetEvalAddCount(uint32_t evalAddCount0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetKeySwitchCount(uint32_t keySwitchCount0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetEncryptionTechnique(EncryptionTechnique encryptionTechnique0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetMultiplicationTechnique(MultiplicationTechnique multiplicationTechnique0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetPRENumHops(uint32_t PRENumHops0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetMultipartyMode(MultipartyMode multipartyMode0) override {
        DISABLED_FOR_CKKSMOD;
    }
    void SetThresholdNumOfParties(uint32_t thresholdNumOfParties0) override {
        DISABLED_FOR_CKKSMOD;
    }
};
//====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_CKKSMOD_PARAMS_H__
