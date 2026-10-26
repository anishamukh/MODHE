/**
 * @file DPadHE.hpp
 * @brief DPad-HE rank-up and rank-down overflow mapping for cross-relinearization.
 */

#pragma once
#include "openfhe.h"

namespace lbcrypto {
namespace dpad {

struct DPadKeys {
    EvalKey<DCRTModule> crlk_hadamard;
    EvalKey<DCRTModule> crlk_lower;
    EvalKey<DCRTModule> rdk;
};

/**
 * @brief Utility function to copy elements into a DCRTModule.
 */
void SetDCRTPoly(DCRTModule& mod, size_t row, size_t col, const DCRTPoly& poly);

/**
 * @brief Generates the cross-relinearization and rank-down keys.
 * 
 * @param cc_sloppy CryptoContext for Phase A (RankUp / Sloppy parameters).
 * @param cc_strict CryptoContext for Phase B (RankDown / Strict parameters).
 * @param sk The original secret key.
 * @param r The base rank of the module.
 * @param r_ext The extended rank after tensor expansion.
 * @return DPadKeys Struct containing all required evaluation keys.
 */
DPadKeys generate_dpad_keys(
    CryptoContext<DCRTModule> cc_sloppy,
    CryptoContext<DCRTModule> cc_strict,
    PrivateKey<DCRTModule> sk,
    int r, int r_ext
);

/**
 * @brief Phase A: Cross-Relinearization (RankUp).
 * 
 * Multiplies the expanded ciphertext tensor by the sloppy cross-relinearization key.
 * 
 * @param cc_sloppy CryptoContext for Phase A.
 * @param ct_tensor The input tensor ciphertext.
 * @param dpad_keys The evaluation keys containing the Hadamard and Lower Cross-Relin keys.
 * @return A pair of DCRTModule polynomials (c_hat_0, c_hat_1) representing the up-ranked components.
 */
std::pair<DCRTModule, DCRTModule> DPad_RankUp(
    CryptoContext<DCRTModule> cc_sloppy,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys
);

/**
 * @brief Phase B: Overflow Mapping (RankDown).
 * 
 * Maps the overflow rank-components back down to the base rank using the rank-down key.
 * 
 * @param cc_strict CryptoContext for Phase B.
 * @param ct_tensor The original tensor ciphertext.
 * @param dpad_keys The evaluation keys containing the RankDown key.
 * @param c_hat_0 Output component 0 from RankUp.
 * @param c_hat_1 Output component 1 from RankUp.
 * @param r Base rank.
 * @param r_ext Extended rank.
 * @return The fully relinearized DCRTModule Ciphertext.
 */
Ciphertext<DCRTModule> DPad_RankDown(
    CryptoContext<DCRTModule> cc_strict,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys,
    const DCRTModule& c_hat_0,
    const DCRTModule& c_hat_1,
    int r, int r_ext
);

/**
 * @brief End-to-end Relinearization Wrapper.
 * 
 * Sequentially executes Phase A (RankUp) and Phase B (RankDown).
 * 
 * @param cc_sloppy CryptoContext for Phase A.
 * @param cc_strict CryptoContext for Phase B.
 * @param ct_tensor The input tensor ciphertext.
 * @param dpad_keys The DPad keys.
 * @param r Base rank.
 * @param r_ext Extended rank.
 * @return The relinearized ciphertext.
 */
Ciphertext<DCRTModule> DPad_Relin(
    CryptoContext<DCRTModule> cc_sloppy,
    CryptoContext<DCRTModule> cc_strict,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys,
    int r, int r_ext
);


/**
 * @brief High-level wrapper that performs homomorphic multiplication and cross-relinearizes the tensor using DPad-HE.
 * 
 * @param cc_P_hat The sloppy (expanded) CryptoContext.
 * @param cc_P The strict (base) CryptoContext.
 * @param ct1 The first ciphertext (base rank).
 * @param ct2 The second ciphertext (base rank).
 * @param dpad_keys The DPad-HE specific evaluation keys.
 * @param r The base rank of the module (must match cc_P).
 * @param r_ext The extended rank of the module (must match cc_P_hat).
 * @return Ciphertext<DCRTModule> The successfully relinearized ciphertext evaluated at rank r.
 */
Ciphertext<DCRTModule> DPad_EvalMult(CryptoContext<DCRTModule> cc_P_hat, CryptoContext<DCRTModule> cc_P, Ciphertext<DCRTModule> ct1, Ciphertext<DCRTModule> ct2, const DPadKeys& dpad_keys, int r, int r_ext);

} // namespace dpad
} // namespace lbcrypto

