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

#ifndef LBCRYPTO_CRYPTO_CKKSMOD_PKE_H
#define LBCRYPTO_CRYPTO_CKKSMOD_PKE_H

#include "schemebase/base-pke.h"
#include "lattice/lat-hal.h"

#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class PKECKKSMOD : public PKEBase<DCRTModule> {
    using ParmType = typename DCRTModule::Params;
    using IntType  = typename DCRTModule::Integer;
    using DugType  = typename DCRTModule::DugType;
    using DggType  = typename DCRTModule::DggType;
    using TugType  = typename DCRTModule::TugType;

public:
    virtual ~PKECKKSMOD() {}

    KeyPair<DCRTModule> KeyGenInternal(CryptoContext<DCRTModule> cc, bool makeSparse) const override;

    /**
   * Method for encrypting plaintext using LBC
   *
   * @param&publicKey public key used for encryption.
   * @param plaintext copy of the plaintext element. NOTE a copy is passed!
   * That is NOT an error!
   * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
   * cryptocontext if false
   * @param *ciphertext ciphertext which results from encryption.
   */
    Ciphertext<DCRTModule> Encrypt(DCRTModule plaintext, const PublicKey<DCRTModule> publicKey) const override;

    /**
 * Method for encrypting plaintex using LBC
 *
 * @param privateKey private key used for encryption.
 * @param plaintext copy of the plaintext input. NOTE a copy is passed! That
 * is NOT an error!
 * @param doEncryption encrypts if true, embeds (encodes) the plaintext into
 * cryptocontext if false
 * @param *ciphertext ciphertext which results from encryption.
 */
    Ciphertext<DCRTModule> Encrypt(DCRTModule plaintext, const PrivateKey<DCRTModule> privateKey) const override;

    /**
   * Method for decrypting plaintext with noise flooding
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult Decrypt(ConstCiphertext<DCRTModule> ciphertext, const PrivateKey<DCRTModule> privateKey,
                          NativePoly* plaintext) const override;

    /**
   * Method for decrypting plaintext with noise flooding
   *
   * @param &privateKey private key used for decryption.
   * @param &ciphertext ciphertext id decrypted.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
    DecryptResult Decrypt(ConstCiphertext<DCRTModule> ciphertext, const PrivateKey<DCRTModule> privateKey,
                          Poly* plaintext) const override;

    std::shared_ptr<std::vector<DCRTModule>> EncryptZeroCore(const PrivateKey<DCRTModule> privateKey,
                                                             const std::shared_ptr<ParmType> params) const override;

    std::shared_ptr<std::vector<DCRTModule>> EncryptZeroCore(const PublicKey<DCRTModule> publicKey,
                                                             const std::shared_ptr<ParmType> params) const override;

    DCRTModule DecryptCore(const std::vector<DCRTModule>& cv, const PrivateKey<DCRTModule> privateKey) const override;
    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar) const {
        ar(cereal::base_class<PKEBase<DCRTModule>>(this));
    }

    template <class Archive>
    void load(Archive& ar) {
        ar(cereal::base_class<PKEBase<DCRTModule>>(this));
    }

    std::string SerializedObjectName() const {
        return "PKECKKSMOD";
    }
};

}  // namespace lbcrypto

#endif
