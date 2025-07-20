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
  Unit tests for the CKKS scheme
 */

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <iterator>

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    ADD_PACKED = 0,
    MULT_PACKED,
    AUTO_LEVEL_REDUCE,
    ADD_PACKED_PRECISION,
    MULT_PACKED_PRECISION,
    SMALL_SCALING_MOD_SIZE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case ADD_PACKED:
            typeName = "ADD_PACKED";
            break;
        case MULT_PACKED:
            typeName = "MULT_PACKED";
            break;
        case AUTO_LEVEL_REDUCE:
            typeName = "AUTO_LEVEL_REDUCE";
            break;
        case ADD_PACKED_PRECISION:
            typeName = "ADD_PACKED_PRECISION";
            break;
        case MULT_PACKED_PRECISION:
            typeName = "MULT_PACKED_PRECISION";
            break;
        case SMALL_SCALING_MOD_SIZE:
            typeName = "SMALL_SCALING_MOD_SIZE";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSMod {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    // ........
    uint32_t slots;
    ScalingTechnique lowerPrecisionTechnique;
    ScalingTechnique higherPrecisionTechnique;


    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }
    std::string toString() const {
        std::stringstream ss;
        ss << "testCaseType [" << testCaseType << "], " << params.toString();
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSMod>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSMod& test) {
    return os << test.toString();
}
//===========================================================================================================
/***
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
constexpr usint RING_DIM      = 512;
constexpr usint RING_DIM_HALF = 256;
constexpr usint DSIZE         = 10;
constexpr usint BATCH         = 8;
constexpr usint MODULE_RANK   = 4;
#if NATIVEINT != 128 && !defined(__EMSCRIPTEN__)
constexpr usint RING_DIM_PREC = 2048;  // for test cases with approximation error comparison only
#endif
// MIN_PRECISION_DIFF is the minimal difference expected between approximation error/precision for FLEXIBLEAUTO and FLEXIBLEAUTOEXT
constexpr double MIN_PRECISION_DIFF = 1.5;
// clang-format off
static std::vector<TEST_CASE_UTCKKSMod> testCases = {
    // TestType,  Descr, Scheme,         RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { ADD_PACKED, "03", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { ADD_PACKED, "04", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
#if NATIVEINT != 128
    { ADD_PACKED, "06", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { ADD_PACKED, "08", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    // TestType,            Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { ADD_PACKED_PRECISION, "01", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0,     FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
    // Special cases when mult depth = 0 and FLEXIBLEAUTO* modes are used; checks that the scaling factor set correctly
#endif
    // ==========================================
    // TestType,  Descr, Scheme,         RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { ADD_PACKED, "23", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    { ADD_PACKED, "24", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
#if NATIVEINT != 128
    { ADD_PACKED, "26", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    { ADD_PACKED, "28", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    // TestType,            Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { ADD_PACKED_PRECISION, "21", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32,    FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
#endif
    // ==========================================
    // TestType,  Descr, Scheme,         RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { ADD_PACKED, "33", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    { ADD_PACKED, "34", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
#if NATIVEINT != 128
    { ADD_PACKED, "36", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    { ADD_PACKED, "38", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    // TestType,            Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots,         LowPrec,      HighPrec
    { ADD_PACKED_PRECISION, "31", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF, FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
#endif
    // ==========================================
    // TestType,  Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { MULT_PACKED, "03", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { MULT_PACKED, "04", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
#if NATIVEINT != 128
    { MULT_PACKED, "06", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { MULT_PACKED, "08", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    // TestType,             Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { MULT_PACKED_PRECISION, "01", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0,     FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
    { MULT_PACKED_PRECISION, "03", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0,     FIXEDAUTO,    FLEXIBLEAUTO},
#endif
    // ==========================================
    // TestType,  Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { MULT_PACKED, "13", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { MULT_PACKED, "14", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
#if NATIVEINT != 128
    { MULT_PACKED, "16", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    { MULT_PACKED, "18", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0},
    // TestType,             Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { MULT_PACKED_PRECISION, "11", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0,     FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
    { MULT_PACKED_PRECISION, "13", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   0,     FIXEDAUTO,    FLEXIBLEAUTO},
#endif
    // ==========================================
    // TestType,  Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { MULT_PACKED, "23", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH},
    { MULT_PACKED, "24", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH},
#if NATIVEINT != 128
    { MULT_PACKED, "26", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH},
    { MULT_PACKED, "28", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH},
    // TestType,             Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { MULT_PACKED_PRECISION, "21", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH, FLEXIBLEAUTO, FLEXIBLEAUTOEXT},
    { MULT_PACKED_PRECISION, "23", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   BATCH, FIXEDAUTO,    FLEXIBLEAUTO},
#endif
    // ==========================================
    // TestType,  Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { MULT_PACKED, "33", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    { MULT_PACKED, "34", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
#if NATIVEINT != 128
    { MULT_PACKED, "36", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    { MULT_PACKED, "38", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32},
    // TestType,             Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots, LowPrec,      HighPrec
    { MULT_PACKED_PRECISION, "31", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32,    FLEXIBLEAUTO, FLEXIBLEAUTOEXT },
    { MULT_PACKED_PRECISION, "33", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   32,    FIXEDAUTO,    FLEXIBLEAUTO },
#endif
    // ==========================================
    // TestType,  Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots
    { MULT_PACKED, "43", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    { MULT_PACKED, "44", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
#if NATIVEINT != 128
    { MULT_PACKED, "46", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    { MULT_PACKED, "48", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF},
    // TestType,             Descr, Scheme,         RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, multiparty, decryptnoise, execmode, noiseestimate, rank, Slots,         LowPrec,      HighPrec
    { MULT_PACKED_PRECISION, "41", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF, FLEXIBLEAUTO, FLEXIBLEAUTOEXT },
    { MULT_PACKED_PRECISION, "43", {CKKSMOD_SCHEME, RING_DIM_PREC, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK},   RING_DIM_HALF, FIXEDAUTO,    FLEXIBLEAUTO },
#endif
    // ==========================================
    // TestType,        Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { AUTO_LEVEL_REDUCE, "03", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
    { AUTO_LEVEL_REDUCE, "04", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
#if NATIVEINT != 128
    { AUTO_LEVEL_REDUCE, "06", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
    { AUTO_LEVEL_REDUCE, "08", {CKKSMOD_SCHEME, RING_DIM, 7,     DFLT,     DSIZE, BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
#endif
#if !defined(EMSCRIPTEN)
    // TestType,              Descr, Scheme,        RDim,   MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,    LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { SMALL_SCALING_MOD_SIZE, "01", {CKKSMOD_SCHEME, 32768, 19,        22,       DFLT,  DFLT,    DFLT,       DFLT,          23,       DFLT,         DFLT,   FIXEDMANUAL, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
    { SMALL_SCALING_MOD_SIZE, "02", {CKKSMOD_SCHEME, 32768, 16,        50,       DFLT,  DFLT,    DFLT,       DFLT,          50,       HEStd_NotSet, DFLT,   DFLT,        DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,       DFLT,         DFLT,     DFLT,          MODULE_RANK}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
/**
 * Function to check minimal difference between 2 numeric values
 *
 * @param high    higher value
 * @param low     lower value
 * @param diff    minimal expected difference between high and low
 */
template <typename T>
bool checkMinDiff(const T& high, const T& low, const uint32_t diff) {
    if (high > low)
        return ((high - low) >= diff);
    return false;
}

/**
 * Function to check minimal difference between elements of 2 vectors with numeric values
 *
 * @param high   vector with higher values
 * @param low    vector with lower values
 * @param diff   minimal expected difference between elements in high and low
 */
template <typename V>
bool checkMinDiff(const std::vector<V>& high, const std::vector<V>& low, const uint32_t diff) {
    if (high.size() != low.size())
        return false;

    return std::equal(high.begin(), high.end(), low.begin(),
                      [&diff](const V& high, const V& low) { return checkMinDiff(high, low, diff); });
}

/**
 * Function to check minimal difference between elements of 2 vectors with numeric values
 *
 * @param high   vector with higher values
 * @param low    vector with lower values
 * @param errMsg Debug message to display upon failure
 * @param diff   minimal expected difference between elements in high and low
 */
template <typename V>
void checkMinDiff(const std::vector<V>& high, const std::vector<V>& low, const uint32_t diff,
                  const std::string& errMsg) {
    // print vector values to error message
    std::stringstream ss;
    ss << ": HIGHER precision/LOWER error: [";
    std::copy(high.begin(), high.end(), std::ostream_iterator<V>(ss, " "));
    ss << "]; LOWER precisions/HIGHER error: [";
    std::copy(low.begin(), low.end(), std::ostream_iterator<V>(ss, " "));
    ss << "]";

    std::string msg(errMsg);
    msg += ss.str();
    EXPECT_TRUE(checkMinDiff(high, low, diff)) << msg;
}
//===========================================================================================================
class UTCKKSMod : public ::testing::TestWithParam<TEST_CASE_UTCKKSMod> {
    using Element = DCRTModule;

    // the size for all vectors remains const - 8 elements
    const usint VECTOR_SIZE = 8;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = EPSILON;

    const double epsHigh = 0.00001;

    const double factor = 1 << 25;

    const std::vector<std::complex<double>> vectorOfInts0_7{0, 1, 2, 3, 4, 5, 6, 7};
    const std::vector<std::complex<double>> vectorOfInts0_7_Neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<std::complex<double>> vectorOfInts0_7_Add{0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5};
    const std::vector<std::complex<double>> vectorOfInts0_7_AddLargeScalar{
        0 + factor, 1 + factor, 2 + factor, 3 + factor, 4 + factor, 5 + factor, 6 + factor, 7 + factor};
    const std::vector<std::complex<double>> vectorOfInts0_7_Sub{-0.5, 0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5};
    const std::vector<std::complex<double>> vectorOfInts0_7neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<std::complex<double>> vectorOfInts7_0{7, 6, 5, 4, 3, 2, 1, 0};

    const std::vector<std::complex<double>> vectorOfInts1_8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<std::complex<double>> vectorOfInts1_8neg{-1, -2, -3, -4, -5, -6, -7, -8};
    const std::vector<std::complex<double>> vectorOfInts8_1{8, 7, 6, 5, 4, 3, 2, 1};

    const std::vector<std::complex<double>> vectorOfInts1s{1, 1, 1, 1, 1, 1, 1, 1};  // all 1's
    const std::vector<std::complex<double>> vectorOfInts1sNeg{-1, -1, -1, -1, -1, -1, -1, -1};  // all 1's

    // CalculateApproximationError() calculates the precision number (or approximation error).
    // The higher the precision, the less the error.
    template <typename T>
    double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                       const std::vector<std::complex<double>>& expectedResult) {
        OPENFHE_THROW("CalculateApproximationError() is not implemented for this datatype");
    }

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTModule>::ReleaseAllContexts();
    }

    template <typename T>
    bool UnitTest_Add_Packed(const TEST_CASE_UTCKKSMod& testData, std::vector<T>& approximationErrors,
                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateModuleContext(testData.params));

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7, 1, 0, nullptr, testData.slots);
            Plaintext plaintext1AddScalar =
                cc->MakeCKKSPackedPlaintext(vectorOfInts0_7_Add, 1, 0, nullptr, testData.slots);
            Plaintext plaintext1AddLargeScalar =
                cc->MakeCKKSPackedPlaintext(vectorOfInts0_7_AddLargeScalar, 1, 0, nullptr, testData.slots);
            Plaintext plaintext1SubScalar =
                cc->MakeCKKSPackedPlaintext(vectorOfInts0_7_Sub, 1, 0, nullptr, testData.slots);
            Plaintext negatives1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7neg, 1, 0, nullptr, testData.slots);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts7_0, 1, 0, nullptr, testData.slots);

            Plaintext plaintextAdd = cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>(VECTOR_SIZE, 7), 1,
                                                                 0, nullptr, testData.slots);  // vector of 7s
            Plaintext plaintextSub = cc->MakeCKKSPackedPlaintext(
                std::vector<std::complex<double>>{-7, -5, -3, -1, 1, 3, 5, 7}, 1, 0, nullptr, testData.slots);


            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1         = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext1_mutable = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2         = cc->Encrypt(kp.publicKey, plaintext2);


            // Testing EvalAdd
            Plaintext results;
            Ciphertext<Element> cResult;


            cResult = cc->EvalAdd(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalAdd fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue()));


            cc->EvalAddInPlace(ciphertext1_mutable, ciphertext2);
            cc->Decrypt(kp.secretKey, ciphertext1_mutable, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalAddInPlace fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            // Testing operator+
            cResult = ciphertext1 + ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " operator+ fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            // Testing operator+=
            Ciphertext<Element> caddInplace(ciphertext1);
            caddInplace += ciphertext2;
            cc->Decrypt(kp.secretKey, caddInplace, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " operator+= fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            cResult = cc->EvalSub(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalSub fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            // Testing operator-
            cResult = ciphertext1 - ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " operator- fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            // Testing operator-=
            Ciphertext<Element> csubInplace(ciphertext1);
            csubInplace -= ciphertext2;
            cc->Decrypt(kp.secretKey, csubInplace, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " operator-= fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue()));
            

            // Testing EvalNegate
            cResult = cc->EvalNegate(ciphertext1);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(negatives1->GetLength());
            checkEquality(negatives1->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalNegate fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(negatives1->GetCKKSPackedValue(), results->GetCKKSPackedValue()));


            return true;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        return false;
    }

    void UnitTest_Add_Packed(const TEST_CASE_UTCKKSMod& testData, const std::string& failmsg = std::string()) {
        std::vector<double> precisions;
        UnitTest_Add_Packed(testData, precisions, failmsg);
    }

    void UnitTest_Add_Packed_Precision(const TEST_CASE_UTCKKSMod& testData,
                                       const std::string& failmsg = std::string()) {
        TEST_CASE_UTCKKSMod testDataLocal(testData);

        std::vector<double> lowPrecisions;
        CryptoContextFactory<DCRTModule>::ReleaseAllContexts();
        testDataLocal.params.scalTech = testDataLocal.lowerPrecisionTechnique;
        if (!UnitTest_Add_Packed(testDataLocal, lowPrecisions, failmsg))
            return;

        std::vector<double> highPrecisions;
        CryptoContextFactory<DCRTModule>::ReleaseAllContexts();
        testDataLocal.params.scalTech = testDataLocal.higherPrecisionTechnique;
        if (!UnitTest_Add_Packed(testDataLocal, highPrecisions, failmsg))
            return;

        checkMinDiff(highPrecisions, lowPrecisions, MIN_PRECISION_DIFF,
                     failmsg + " Approximation errors' comparison failed");
    }

    template <typename T>
    bool UnitTest_Mult_Packed(const TEST_CASE_UTCKKSMod& testData, std::vector<T>& approximationErrors,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateModuleContext(testData.params));

            Plaintext plaintext1    = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7, 1, 0, nullptr, testData.slots);
            Plaintext plaintext2    = cc->MakeCKKSPackedPlaintext(vectorOfInts7_0, 1, 0, nullptr, testData.slots);
            Plaintext plaintextNeg  = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7_Neg, 1, 0, nullptr, testData.slots);
            Plaintext plaintextMult = cc->MakeCKKSPackedPlaintext(
                std::vector<std::complex<double>>({0, 6, 10, 12, 12, 10, 6, 0}), 1, 0, nullptr, testData.slots);
            Plaintext plaintextLarge = cc->MakeCKKSPackedPlaintext(
                std::vector<std::complex<double>>({factor, factor, 0, 0, 0, 0, 0, 0}), 1, 0, nullptr, testData.slots);
            Plaintext plaintextLargeMult = cc->MakeCKKSPackedPlaintext(
                std::vector<std::complex<double>>({7 * factor, 6 * factor, 0, 0, 0, 0, 0, 0}), 1, 0, nullptr,
                testData.slots);
            Plaintext plaintext1s = cc->MakeCKKSPackedPlaintext(vectorOfInts1s, 1, 0, nullptr, testData.slots);
            Plaintext plaintextNeg1s = cc->MakeCKKSPackedPlaintext(vectorOfInts1sNeg, 1, 0, nullptr, testData.slots);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();

            // Generate multiplication keys
            cc->EvalMultModKeyGen(kp.secretKey);


            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
            Ciphertext<Element> ciphertext1s = cc->Encrypt(kp.publicKey, plaintext1s);
            Ciphertext<Element> ciphertextNeg1s = cc->Encrypt(kp.publicKey, plaintextNeg1s);

            // adding an extra multiplication so that precision tests could clearly
            // show differences between different scaling techniques
            ciphertext1 = cc->EvalMultAndRelinearize(ciphertext1, ciphertext1s);
            cc->RescaleInPlace(ciphertext1);
            ciphertext2 = cc->EvalMultAndRelinearize(ciphertext2, ciphertext1s);
            cc->RescaleInPlace(ciphertext2);

            // Testing EvalMultAndRelinearize
            Ciphertext<Element> cResult;
            Plaintext results;
            cResult = cc->EvalMultAndRelinearize(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalMultAndRelinearize fails");
            approximationErrors.emplace_back(
                CalculateApproximationError<T>(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue()));

            // Testing EvalMultAndRelinearize ciphertext * positive double
            cResult = cc->EvalMultAndRelinearize(ciphertext1, ciphertext1s);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintext1->GetLength());
            checkEquality(plaintext1->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalMultAndRelinearize Ct and positive double fails");

            // Testing EvalMultAndRelinearize ciphertext * negative double
            cResult = cc->EvalMultAndRelinearize(ciphertext1, ciphertextNeg1s);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextNeg->GetLength());
            std::stringstream buffer1;
            buffer1 << "should be: " << plaintextNeg->GetCKKSPackedValue()
                    << " - we get: " << results->GetCKKSPackedValue();
            checkEquality(plaintextNeg->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " EvalMultAndRelinearize Ct and negative double fails; " + buffer1.str());

            return true;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        return false;
    }

    void UnitTest_Mult_Packed(const TEST_CASE_UTCKKSMod& testData, const std::string& failmsg = std::string()) {
        std::vector<double> precisions;
        UnitTest_Mult_Packed(testData, precisions, failmsg);
    }

    void UnitTest_Mult_Packed_Precision(const TEST_CASE_UTCKKSMod& testData,
                                        const std::string& failmsg = std::string()) {
        TEST_CASE_UTCKKSMod testDataLocal(testData);

        std::vector<double> lowPrecisions;
        CryptoContextFactory<DCRTModule>::ReleaseAllContexts();
        testDataLocal.params.scalTech = testDataLocal.lowerPrecisionTechnique;
        if (!UnitTest_Mult_Packed(testDataLocal, lowPrecisions, failmsg))
            return;

        std::vector<double> highPrecisions;
        CryptoContextFactory<DCRTModule>::ReleaseAllContexts();
        testDataLocal.params.scalTech = testDataLocal.higherPrecisionTechnique;
        if (!UnitTest_Mult_Packed(testDataLocal, highPrecisions, failmsg))
            return;

        checkMinDiff(highPrecisions, lowPrecisions, MIN_PRECISION_DIFF,
                     failmsg + " Approximation errors' comparison failed");
    }

    void UnitTest_AutoLevelReduce(const TEST_CASE_UTCKKSMod& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateModuleContext(testData.params));

            std::vector<std::complex<double>> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);

            std::vector<std::complex<double>> vectorOfInts2(vectorOfInts7_0);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

            std::vector<std::complex<double>> pCtMult(VECTOR_SIZE);
            std::vector<std::complex<double>> pCtMult3(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt3(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt3_b(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt4(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt5(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt6(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt7(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_5(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_6(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_7(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt8(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt9(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt10(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt11(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt12(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt13(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt14(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                pCtMult[i] = vectorOfInts1[i] * vectorOfInts2[i];
                pCt3[i]    = pCtMult[i] + vectorOfInts1[i];
                pCt4[i]    = pCtMult[i] - vectorOfInts1[i];
                pCt5[i]    = pCtMult[i] * vectorOfInts1[i];
                pCt6[i]    = vectorOfInts1[i] + pCtMult[i];
                pCt7[i]    = vectorOfInts1[i] - pCtMult[i];
                auto tmp =
                    (vectorOfInts1[i] * vectorOfInts1[i] + vectorOfInts1[i] * vectorOfInts1[i]) * vectorOfInts1[i];
                pCt_5[i]    = tmp + vectorOfInts2[i];
                pCt_6[i]    = tmp - vectorOfInts2[i];
                pCt_7[i]    = tmp * vectorOfInts2[i];
                pCt8[i]     = vectorOfInts1[i] * pCtMult[i];
                pCtMult3[i] = pCtMult[i] * vectorOfInts1[i] * vectorOfInts1[i];
                pCt9[i]     = pCtMult3[i] + vectorOfInts1[i];
                pCt10[i]    = pCtMult3[i] - vectorOfInts1[i];
                pCt11[i]    = pCtMult3[i] * vectorOfInts1[i];
                pCt12[i]    = vectorOfInts1[i] + pCtMult3[i];
                pCt13[i]    = vectorOfInts1[i] - pCtMult3[i];
                pCt14[i]    = vectorOfInts1[i] * pCtMult3[i];
            }
            Plaintext plaintextCt3  = cc->MakeCKKSPackedPlaintext(pCt3);
            Plaintext plaintextCt4  = cc->MakeCKKSPackedPlaintext(pCt4);
            Plaintext plaintextCt5  = cc->MakeCKKSPackedPlaintext(pCt5);
            Plaintext plaintextCt6  = cc->MakeCKKSPackedPlaintext(pCt6);
            Plaintext plaintextCt7  = cc->MakeCKKSPackedPlaintext(pCt7);
            Plaintext plaintextCt_5 = cc->MakeCKKSPackedPlaintext(pCt_5);
            Plaintext plaintextCt_6 = cc->MakeCKKSPackedPlaintext(pCt_6);
            Plaintext plaintextCt_7 = cc->MakeCKKSPackedPlaintext(pCt_7);
            Plaintext plaintextCt8  = cc->MakeCKKSPackedPlaintext(pCt8);
            Plaintext plaintextCt9  = cc->MakeCKKSPackedPlaintext(pCt9);
            Plaintext plaintextCt10 = cc->MakeCKKSPackedPlaintext(pCt10);
            Plaintext plaintextCt11 = cc->MakeCKKSPackedPlaintext(pCt11);
            Plaintext plaintextCt12 = cc->MakeCKKSPackedPlaintext(pCt12);
            Plaintext plaintextCt13 = cc->MakeCKKSPackedPlaintext(pCt13);
            Plaintext plaintextCt14 = cc->MakeCKKSPackedPlaintext(pCt14);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultModKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ct  = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ct2 = cc->Encrypt(kp.publicKey, plaintext2);

            auto ctMul = cc->EvalMultAndRelinearize(ct, ct2);
            auto ctRed = cc->ModReduce(ctMul);

            Plaintext results;
            // Addition with tower diff = 1
            auto ct3 = cc->EvalAdd(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct3, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " addition with tower diff = 1 fails");

            // in-place addition with tower diff = 1
            auto ctRedClone = ctRed->Clone();
            cc->EvalAddInPlace(ctRedClone, ct);
            cc->Decrypt(kp.secretKey, ctRedClone, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " in-place addition with tower diff = 1 fails");

            // Subtraction with tower diff = 1
            auto ct4 = cc->EvalSub(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct4, &results);
            results->SetLength(plaintextCt4->GetLength());
            checkEquality(plaintextCt4->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " subtraction with tower diff = 1 fails");

            // Multiplication with tower diff = 1
            auto ct5 = cc->EvalMultAndRelinearize(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct5, &results);
            results->SetLength(plaintextCt5->GetLength());
            checkEquality(plaintextCt5->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " multiplication with tower diff = 1 fails");

            // Addition with tower diff = 1 (inputs reversed)
            auto ct6 = cc->EvalAdd(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct6, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " addition (reverse) with tower diff = 1 fails");

            // in-place addition with tower diff = 1 (inputs reversed)
            Ciphertext<Element> ctClone = ct->Clone();
            cc->EvalAddInPlace(ctClone, ctRed);
            cc->Decrypt(kp.secretKey, ctClone, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " in-place addition (reverse) with tower diff = 1 fails");

            // Subtraction with tower diff = 1 (inputs reversed)
            auto ct7 = cc->EvalSub(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct7, &results);
            results->SetLength(plaintextCt7->GetLength());
            checkEquality(plaintextCt7->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " subtraction (reverse) with tower diff = 1 fails");

            // Multiplication with tower diff = 1 (inputs reversed)
            auto ct8 = cc->EvalMultAndRelinearize(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct8, &results);
            results->SetLength(plaintextCt8->GetLength());
            checkEquality(plaintextCt8->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " multiplication (reverse) with tower diff = 1 fails");

            auto ctMul2 = cc->EvalMultAndRelinearize(ctRed, ct);
            auto ctRed2 = cc->ModReduce(ctMul2);
            auto ctMul3 = cc->EvalMultAndRelinearize(ctRed2, ct);
            auto ctRed3 = cc->ModReduce(ctMul3);

            // Addition with more than 1 level difference
            auto ct9 = cc->EvalAdd(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct9, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " addition with tower diff > 1 fails");

            // In-place addition with more than 1 level difference
            auto ctRed3Clone = ctRed3->Clone();
            cc->EvalAddInPlace(ctRed3Clone, ct);
            cc->Decrypt(kp.secretKey, ctRed3Clone, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " in-place addition with tower diff > 1 fails");

            // Subtraction with more than 1 level difference
            auto ct10 = cc->EvalSub(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct10, &results);
            results->SetLength(plaintextCt10->GetLength());
            checkEquality(plaintextCt10->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                          failmsg + " in-place addition with tower diff > 1 fails");

            // Multiplication with more than 1 level difference
            auto ct11 = cc->EvalMultAndRelinearize(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct11, &results);
            results->SetLength(plaintextCt11->GetLength());
            std::stringstream buffer;
            buffer << plaintextCt11->GetCKKSPackedValue() << " - we get: " << results->GetCKKSPackedValue();
            checkEquality(plaintextCt11->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                          failmsg + " multiplication with tower diff > 1 fails" + buffer.str());

            // Addition with more than 1 level difference (inputs reversed)
            auto ct12 = cc->EvalAdd(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct12, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " addition (reverse) with tower diff > 1 fails");

            // In-place addition with more than 1 level difference (inputs reversed)
            ctClone = ct->Clone();
            cc->EvalAddInPlace(ctClone, ctRed3);
            cc->Decrypt(kp.secretKey, ctClone, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " in-place addition (reverse) with tower diff > 1 fails");

            // Subtraction with more than 1 level difference (inputs reversed)
            auto ct13 = cc->EvalSub(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct13, &results);
            results->SetLength(plaintextCt13->GetLength());
            checkEquality(plaintextCt13->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                          failmsg + " subtraction (reverse) with tower diff > 1 fails");

            // Multiplication with more than 1 level difference (inputs reversed)
            auto ct14 = cc->EvalMultAndRelinearize(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct14, &results);
            results->SetLength(plaintextCt14->GetLength());
            checkEquality(plaintextCt14->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                          failmsg + " multiplication (reverse) with tower diff > 1 fails");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_Small_ScalingModSize(const TEST_CASE_UTCKKSMod& testData,
                                       const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateModuleContext(testData.params));
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

template <>
double UTCKKSMod::CalculateApproximationError<double>(const std::vector<std::complex<double>>& result,
                                                      const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW("Cannot compare vectors with different numbers of elements");

    // using the Euclidean norm
    double avrg = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        avrg += std::pow(std::abs(result[i].real() - expectedResult[i].real()), 2);
    }

    avrg = std::sqrt(avrg) / result.size();  // get the average
    return std::abs(std::log2(avrg));
}

// template<>
// uint32_t UTCKKSMod::CalculateApproximationError<int>(
//    const std::vector<std::complex<double>>& result,
//    const std::vector<std::complex<double>>& expectedResult) {
//
//    double err = CalculateApproximationError<double>(result, expectedResult);
//    return std::round(err * 10) / 10; // should return an unsigned integer
// }

//===========================================================================================================
TEST_P(UTCKKSMod, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case ADD_PACKED:
            UnitTest_Add_Packed(test, test.buildTestName());
            break;
        case MULT_PACKED:
            UnitTest_Mult_Packed(test, test.buildTestName());
            break;
        case AUTO_LEVEL_REDUCE:
            UnitTest_AutoLevelReduce(test, test.buildTestName());
            break;
        case ADD_PACKED_PRECISION:
            UnitTest_Add_Packed_Precision(test, test.buildTestName());
            break;
        case MULT_PACKED_PRECISION:
            UnitTest_Mult_Packed_Precision(test, test.buildTestName());
            break;
        case SMALL_SCALING_MOD_SIZE:
            UnitTest_Small_ScalingModSize(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSMod, ::testing::ValuesIn(testCases), testName);
