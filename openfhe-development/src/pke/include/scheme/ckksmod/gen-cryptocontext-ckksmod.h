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
  API to generate CKKSMod crypto context
 */

#ifndef __GEN_CRYPTOCONTEXT_CKKSMOD_H__
#define __GEN_CRYPTOCONTEXT_CKKSMOD_H__

#include "lattice/lat-hal.h"
#include "scheme/ckksmod/gen-cryptocontext-ckksmod-internal.h"
#include "scheme/ckksmod/gen-cryptocontext-ckksmod-params.h"
#include "scheme/ckksmod/ckksmod-cryptoparameters.h"
#include "scheme/ckksmod/ckksmod-scheme.h"
#include "scheme/gen-cryptocontext-params-validation.h"
#include "cryptocontextfactory.h"

namespace lbcrypto {

class CryptoContextCKKSMod {
    using Element = DCRTModule;

public:
    using ContextType               = CryptoContext<Element>;  // required by GenCryptoContext() in gen-cryptocontext.h
    using Factory                   = CryptoContextFactory<Element>;
    using PublicKeyEncryptionScheme = SchemeCKKSMod;
    using CryptoParams              = CryptoParametersCKKSMod;

    static CryptoContext<Element> genCryptoContext(const CCParams<CryptoContextCKKSMod>& parameters) {
        validateParametersForCryptocontext(parameters);
        return genCryptoContextCKKSModInternal<CryptoContextCKKSMod, Element>(parameters);
    }
};

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_CKKSMOD_H__
