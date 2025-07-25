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
  Collection of parameter default values for different schemes
 */

#ifndef __GEN_CRYPTOCONTEXT_PARAMS_DEFAULTS_H__
#define __GEN_CRYPTOCONTEXT_PARAMS_DEFAULTS_H__

#include "lattice/stdlatticeparms.h"  // SecurityLevel
#include "scheme/scheme-id.h"         // SCHEME
#include "utils/inttypes.h"
#include "constants.h"

namespace lbcrypto {

namespace CKKSRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme               = CKKSRNS_SCHEME;
constexpr PlaintextModulus ptModulus  = 0;
constexpr uint32_t digitSize          = 0;
constexpr float standardDeviation     = 3.19f;
constexpr SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
constexpr uint32_t maxRelinSkDeg      = 2;
constexpr KeySwitchTechnique ksTech   = HYBRID;
// Backend-specific settings for CKKS
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
constexpr ScalingTechnique scalTech = FIXEDAUTO;
constexpr uint32_t firstModSize     = 89;
constexpr uint32_t scalingModSize   = 78;
#else
constexpr ScalingTechnique scalTech = FLEXIBLEAUTOEXT;
constexpr uint32_t firstModSize     = 60;
constexpr uint32_t scalingModSize   = 50;
#endif
constexpr uint32_t batchSize                                = 0;
constexpr uint32_t numLargeDigits                           = 0;
constexpr uint32_t multiplicativeDepth                      = 1;
constexpr SecurityLevel securityLevel                       = HEStd_128_classic;
constexpr uint32_t ringDim                                  = 0;
constexpr uint32_t evalAddCount                             = 0;
constexpr uint32_t keySwitchCount                           = 0;
constexpr EncryptionTechnique encryptionTechnique           = STANDARD;
constexpr MultiplicationTechnique multiplicationTechnique   = HPS;
constexpr uint32_t PRENumHops                               = 0;
constexpr ProxyReEncryptionMode PREMode                     = INDCPA;
constexpr MultipartyMode multipartyMode                     = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode executionMode                       = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryptionNoiseMode           = FIXED_NOISE_DECRYPT;
constexpr double noiseEstimate                              = 0.0;
constexpr double desiredPrecision                           = 25.0;
constexpr uint32_t statisticalSecurity                      = 30;
constexpr uint32_t numAdversarialQueries                    = 1;
constexpr uint32_t thresholdNumOfParties                    = 1;
constexpr COMPRESSION_LEVEL interactiveBootCompressionLevel = SLACK;
constexpr uint32_t moduleRank                               = 1;
};  // namespace CKKSRNS_SCHEME_DEFAULTS

namespace CKKSMOD_SCHEME_DEFAULTS {
constexpr SCHEME scheme               = CKKSRNS_SCHEME;
constexpr PlaintextModulus ptModulus  = 0;
constexpr uint32_t digitSize          = 0;
constexpr float standardDeviation     = 3.19f;
constexpr SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
constexpr uint32_t maxRelinSkDeg      = 2;
constexpr KeySwitchTechnique ksTech   = HYBRID;
// Backend-specific settings for CKKS
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
constexpr ScalingTechnique scalTech = FIXEDAUTO;
constexpr uint32_t firstModSize     = 89;
constexpr uint32_t scalingModSize   = 78;
#else
constexpr ScalingTechnique scalTech = FLEXIBLEAUTOEXT;
constexpr uint32_t firstModSize     = 60;
constexpr uint32_t scalingModSize   = 50;
#endif
constexpr uint32_t batchSize                                = 0;
constexpr uint32_t numLargeDigits                           = 0;
constexpr uint32_t multiplicativeDepth                      = 1;
constexpr SecurityLevel securityLevel                       = HEStd_128_classic;
constexpr uint32_t ringDim                                  = 0;
constexpr uint32_t evalAddCount                             = 0;
constexpr uint32_t keySwitchCount                           = 0;
constexpr EncryptionTechnique encryptionTechnique           = STANDARD;
constexpr MultiplicationTechnique multiplicationTechnique   = HPS;
constexpr uint32_t PRENumHops                               = 0;
constexpr ProxyReEncryptionMode PREMode                     = INDCPA;
constexpr MultipartyMode multipartyMode                     = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode executionMode                       = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryptionNoiseMode           = FIXED_NOISE_DECRYPT;
constexpr double noiseEstimate                              = 0.0;
constexpr double desiredPrecision                           = 25.0;
constexpr uint32_t statisticalSecurity                      = 30;
constexpr uint32_t numAdversarialQueries                    = 1;
constexpr uint32_t thresholdNumOfParties                    = 1;
constexpr COMPRESSION_LEVEL interactiveBootCompressionLevel = SLACK;
constexpr uint32_t moduleRank                               = 2;
};  // namespace CKKSRNS_SCHEME_DEFAULTS

namespace BFVRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme                = BFVRNS_SCHEME;
constexpr PlaintextModulus ptModulus   = 0;
constexpr uint32_t digitSize           = 0;
constexpr float standardDeviation      = 3.19f;
constexpr SecretKeyDist secretKeyDist  = UNIFORM_TERNARY;
constexpr uint32_t maxRelinSkDeg       = 2;
constexpr KeySwitchTechnique ksTech    = BV;
constexpr ScalingTechnique scalTech    = NORESCALE;
constexpr uint32_t firstModSize        = 0;
constexpr uint32_t batchSize           = 0;
constexpr uint32_t numLargeDigits      = 0;
constexpr uint32_t multiplicativeDepth = 1;
#if defined(HAVE_INT128) || NATIVEINT != 64
constexpr uint32_t scalingModSize = 60;
#else
constexpr uint32_t scalingModSize = 57;
#endif
constexpr SecurityLevel securityLevel                       = HEStd_128_classic;
constexpr uint32_t ringDim                                  = 0;
constexpr uint32_t evalAddCount                             = 0;
constexpr uint32_t keySwitchCount                           = 0;
constexpr EncryptionTechnique encryptionTechnique           = STANDARD;
constexpr MultiplicationTechnique multiplicationTechnique   = HPSPOVERQLEVELED;
constexpr uint32_t PRENumHops                               = 0;
constexpr ProxyReEncryptionMode PREMode                     = INDCPA;
constexpr MultipartyMode multipartyMode                     = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode executionMode                       = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryptionNoiseMode           = FIXED_NOISE_DECRYPT;
constexpr double noiseEstimate                              = 0.0;
constexpr double desiredPrecision                           = 0.0;
constexpr uint32_t statisticalSecurity                      = 0;
constexpr uint32_t numAdversarialQueries                    = 0;
constexpr uint32_t thresholdNumOfParties                    = 1;
constexpr COMPRESSION_LEVEL interactiveBootCompressionLevel = SLACK;
constexpr uint32_t moduleRank                               = 1;
};  // namespace BFVRNS_SCHEME_DEFAULTS

namespace BGVRNS_SCHEME_DEFAULTS {
constexpr SCHEME scheme                                     = BGVRNS_SCHEME;
constexpr PlaintextModulus ptModulus                        = 0;
constexpr uint32_t digitSize                                = 0;
constexpr float standardDeviation                           = 3.19f;
constexpr SecretKeyDist secretKeyDist                       = UNIFORM_TERNARY;
constexpr uint32_t maxRelinSkDeg                            = 2;
constexpr KeySwitchTechnique ksTech                         = HYBRID;
constexpr ScalingTechnique scalTech                         = FLEXIBLEAUTOEXT;
constexpr uint32_t firstModSize                             = 0;
constexpr uint32_t batchSize                                = 0;
constexpr uint32_t numLargeDigits                           = 0;
constexpr uint32_t multiplicativeDepth                      = 1;
constexpr uint32_t scalingModSize                           = 0;
constexpr SecurityLevel securityLevel                       = HEStd_128_classic;
constexpr uint32_t ringDim                                  = 0;
constexpr uint32_t evalAddCount                             = 5;
constexpr uint32_t keySwitchCount                           = 3;
constexpr EncryptionTechnique encryptionTechnique           = STANDARD;
constexpr MultiplicationTechnique multiplicationTechnique   = HPS;
constexpr uint32_t PRENumHops                               = 0;
constexpr ProxyReEncryptionMode PREMode                     = INDCPA;
constexpr MultipartyMode multipartyMode                     = FIXED_NOISE_MULTIPARTY;
constexpr ExecutionMode executionMode                       = EXEC_EVALUATION;
constexpr DecryptionNoiseMode decryptionNoiseMode           = FIXED_NOISE_DECRYPT;
constexpr double noiseEstimate                              = 0.0;
constexpr double desiredPrecision                           = 0.0;
constexpr uint32_t statisticalSecurity                      = 30;
constexpr uint32_t numAdversarialQueries                    = 1;
constexpr uint32_t thresholdNumOfParties                    = 1;
constexpr COMPRESSION_LEVEL interactiveBootCompressionLevel = SLACK;
constexpr uint32_t moduleRank                               = 1;
};  // namespace BGVRNS_SCHEME_DEFAULTS

//====================================================================================================================

}  // namespace lbcrypto

#endif  // __GEN_CRYPTOCONTEXT_PARAMS_DEFAULTS_H__
