#include "DPadHE.hpp"

namespace lbcrypto {
namespace dpad {

// QUIRK: DCRTModule's internal m_vectors array is private; must overwrite elements manually tower-by-tower.
void SetDCRTPoly(DCRTModule& mod, size_t row, size_t col, const DCRTPoly& poly) {
    for (size_t i = 0; i < poly.GetNumOfElements(); i++) {
        mod.SetElementAtIndex(row, col, i, poly.GetElementAtIndex(i));
    }
}

DPadKeys generate_dpad_keys(
    CryptoContext<DCRTModule> cc_sloppy,
    CryptoContext<DCRTModule> cc_strict,
    PrivateKey<DCRTModule> sk,
    int r, int r_ext
) {
    // s: The original baseline secret key (e.g. [s0, s1])
    auto s = sk->GetPrivateElement();
    auto dcrtParams = s.GetParams();
    DCRTPoly::TugType tug_gen;

    // s_expand: The expanded secret key [s0, s1, s']
    // QUIRK: OpenFHE ModHE assumes column vectors; must transpose to (rows, 1) to prevent key corruption.
    DCRTModule s_expand(dcrtParams, EVALUATION, true, r_ext, 1);
    for (int i = 0; i < r; i++) {
        SetDCRTPoly(s_expand, i, 0, s.GetDCRTPolyAt(i));
    }
    // s_prime_cache: Saves s_prime so it isn't deleted when the loop ends
    std::vector<DCRTPoly> s_prime_cache;
    for (int i = r; i < r_ext; i++) {
        // s_prime: A newly generated random temporary secret (s')
        DCRTPoly s_prime(tug_gen, dcrtParams, EVALUATION); 
        SetDCRTPoly(s_expand, i, 0, s_prime);
        s_prime_cache.push_back(s_prime);
    }
    
    // s_expand_key_sloppy: C++ wrapper turning s_expand into a PrivateKey object for OpenFHE
    PrivateKey<DCRTModule> s_expand_key_sloppy = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc_sloppy);
    s_expand_key_sloppy->SetPrivateElement(std::move(s_expand));

    // QUIRK: EvalMultNoRelin splits quadratic tensors into Hadamard and Lower-Triangle components; we must generate 2 separate keys.
    DCRTModule s_tensor_hadamard(dcrtParams, EVALUATION, true, r, 1);
    // Hadamard: Computes the squared/diagonal terms (e.g., s0^2, s1^2)
    for (int i = 0; i < r; i++) {
        SetDCRTPoly(s_tensor_hadamard, i, 0, s.GetDCRTPolyAt(i) * s.GetDCRTPolyAt(i));
    }
    PrivateKey<DCRTModule> s_tensor_hadamard_key_sloppy = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc_sloppy);
    s_tensor_hadamard_key_sloppy->SetPrivateElement(std::move(s_tensor_hadamard));

    // r_lower: Formula for the number of unique mixed pairs (e.g., s0*s1)
    int r_lower = (r * (r - 1)) / 2;
    if (r_lower == 0) r_lower = 1;
    DCRTModule s_tensor_lower(dcrtParams, EVALUATION, true, r_lower, 1);
    int idx = 0;
    // Lower: Computes all unique mixed combinations without repeating (e.g., s0*s1, s0*s2)
    for (int i = 0; i < r; i++) {
        for (int j = i + 1; j < r; j++) {
            SetDCRTPoly(s_tensor_lower, idx++, 0, s.GetDCRTPolyAt(i) * s.GetDCRTPolyAt(j));
        }
    }
    if (idx == 0) SetDCRTPoly(s_tensor_lower, 0, 0, s.GetDCRTPolyAt(0));
    PrivateKey<DCRTModule> s_tensor_lower_key_sloppy = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc_sloppy);
    s_tensor_lower_key_sloppy->SetPrivateElement(std::move(s_tensor_lower));

    DPadKeys dpad;
    // QUIRK: No public API for custom relinearization keys; must manually invoke the low-level KeySwitchGen algorithm.
    auto algo_sloppy = cc_sloppy->GetScheme();
    dpad.crlk_hadamard = algo_sloppy->KeySwitchGen(s_tensor_hadamard_key_sloppy, s_expand_key_sloppy);
    dpad.crlk_lower = algo_sloppy->KeySwitchGen(s_tensor_lower_key_sloppy, s_expand_key_sloppy);

    int r_overflow = r_ext - r;
    // s_prime_mod: C++ wrapper turning s_prime into a DCRTModule
    DCRTModule s_prime_mod(dcrtParams, EVALUATION, true, r_overflow, 1);
    for (int i = 0; i < r_overflow; i++) {
        SetDCRTPoly(s_prime_mod, i, 0, s_prime_cache[i]);
    }
    // s_prime_key_strict: C++ wrapper turning s_prime_mod into a PrivateKey object for OpenFHE
    PrivateKey<DCRTModule> s_prime_key_strict = std::make_shared<PrivateKeyImpl<DCRTModule>>(cc_strict);
    s_prime_key_strict->SetPrivateElement(std::move(s_prime_mod));
    
    auto algo_strict = cc_strict->GetScheme();
    dpad.rdk = algo_strict->KeySwitchGen(s_prime_key_strict, sk);
    return dpad;
}

std::pair<DCRTModule, DCRTModule> DPad_RankUp(
    CryptoContext<DCRTModule> cc_sloppy,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys
) {
    auto elements = ct_tensor->GetElements();
    // QUIRK: Extracting specific separated tensor components from EvalMultNoRelin output.
    auto c2_hadamard = elements[2]; 
    auto c2_lower = elements[3];
    
    // QUIRK: Must explicitly force EVALUATION (NTT) domain; KeySwitchCore crashes if left in COEFFICIENT format.
    c2_hadamard.SetFormat(Format::EVALUATION);
    c2_lower.SetFormat(Format::EVALUATION);
    
    auto algo_sloppy = cc_sloppy->GetScheme();
    auto c_hat_hadamard = algo_sloppy->KeySwitchCore(c2_hadamard, dpad_keys.crlk_hadamard);
    auto c_hat_lower = algo_sloppy->KeySwitchCore(c2_lower, dpad_keys.crlk_lower);
    
    auto c_hat_0 = (*c_hat_hadamard)[0] + (*c_hat_lower)[0];
    auto c_hat_1 = (*c_hat_hadamard)[1] + (*c_hat_lower)[1];
    
    return {c_hat_0, c_hat_1};
}

Ciphertext<DCRTModule> DPad_RankDown(
    CryptoContext<DCRTModule> cc_strict,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys,
    const DCRTModule& c_hat_0,
    const DCRTModule& c_hat_1,
    int r, int r_ext
) {
    auto elements = ct_tensor->GetElements();
    auto c0 = elements[0];
    auto c1 = elements[1];
    
    auto q_params = elements[0].GetParams();
    // QUIRK: ApproxModDown corrupts metadata; bypassing DropColumns by manually extracting clean DCRTPoly elements.
    DCRTModule c_hat_1_base(q_params, EVALUATION, true, 1, r);
    for (int i = 0; i < r; i++) {
        SetDCRTPoly(c_hat_1_base, 0, i, c_hat_1.GetDCRTPolyAt(i));
    }
    
    int r_overflow = r_ext - r;
    DCRTModule c_overflow(q_params, EVALUATION, true, 1, r_overflow);
    for (int i = 0; i < r_overflow; i++) {
        SetDCRTPoly(c_overflow, 0, i, c_hat_1.GetDCRTPolyAt(r + i));
    }
    
    auto algo_strict = cc_strict->GetScheme();
    auto c_tilde = algo_strict->KeySwitchCore(c_overflow, dpad_keys.rdk);
    
    auto c_final_0 = c0 + c_hat_0 + (*c_tilde)[0];
    auto c_final_1 = c1 + c_hat_1_base + (*c_tilde)[1];
    
    auto ct_final = ct_tensor->Clone();
    // QUIRK: Manually reconstructing the ciphertext array due to missing public constructors.
    ct_final->GetElements().clear();
    ct_final->GetElements().push_back(c_final_0);
    ct_final->GetElements().push_back(c_final_1);
    return ct_final;
}

Ciphertext<DCRTModule> DPad_Relin(
    CryptoContext<DCRTModule> cc_sloppy,
    CryptoContext<DCRTModule> cc_strict,
    Ciphertext<DCRTModule>& ct_tensor,
    const DPadKeys& dpad_keys,
    int r, int r_ext
) {
    auto rank_up_res = DPad_RankUp(cc_sloppy, ct_tensor, dpad_keys);
    return DPad_RankDown(cc_strict, ct_tensor, dpad_keys, rank_up_res.first, rank_up_res.second, r, r_ext);
}



Ciphertext<DCRTModule> DPad_EvalMult(CryptoContext<DCRTModule> cc_P_hat, CryptoContext<DCRTModule> cc_P, Ciphertext<DCRTModule> ct1, Ciphertext<DCRTModule> ct2, const DPadKeys& dpad_keys, int r, int r_ext) {
    // QUIRK: Native ModHE EvalMult crashes because it expects standard relin keys. We use EvalMultNoRelin to bypass it.
    auto ct_tensor = cc_P->EvalMultNoRelin(ct1, ct2);
    return DPad_Relin(cc_P_hat, cc_P, ct_tensor, dpad_keys, r, r_ext);
}

} // namespace dpad
} // namespace lbcrypto

