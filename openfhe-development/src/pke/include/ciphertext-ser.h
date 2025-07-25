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
  serialize ciphertexts; include this in any app that needs to serialize them
 */

#ifndef LBCRYPTO_CRYPTO_CIPHERTEXTSER_H
#define LBCRYPTO_CRYPTO_CIPHERTEXTSER_H

#include "ciphertext.h"
#include "utils/serial.h"

extern template class lbcrypto::CiphertextImpl<lbcrypto::Poly>;
extern template class lbcrypto::CiphertextImpl<lbcrypto::NativePoly>;
extern template class lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>;
extern template class lbcrypto::CiphertextImpl<lbcrypto::DCRTModule>;

CEREAL_CLASS_VERSION(lbcrypto::CiphertextImpl<lbcrypto::Poly>,
                     lbcrypto::CiphertextImpl<lbcrypto::Poly>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::CiphertextImpl<lbcrypto::NativePoly>,
                     lbcrypto::CiphertextImpl<lbcrypto::NativePoly>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>,
                     lbcrypto::CiphertextImpl<lbcrypto::DCRTPoly>::SerializedVersion());
CEREAL_CLASS_VERSION(lbcrypto::CiphertextImpl<lbcrypto::DCRTModule>,
                     lbcrypto::CiphertextImpl<lbcrypto::DCRTModule>::SerializedVersion());

#endif
