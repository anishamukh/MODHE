#function for HOMOMORPHIC MULTIPLICATION
def homomorphic_mult(ciphertext1, ciphertext2, level, key):

    c0_qshares1 = ciphertext1[0] 
    c1_qshares1 = ciphertext1[1]

    c0_qshares2 = ciphertext2[0] 
    c1_qshares2 = ciphertext2[1] 

    d0_qshares = []
    d10_qshares = []
    d11_qshares =[]
    d20_qshares = []
    d21_qshares = []
    d3_qshares = []
    d1_qshares = matrix(R, 1, MLWE)
    d2_qshares = matrix(R, 1, MLWE)

    temp = 0
    for j in range(level+1):
        temp = (c0_qshares1[j]*c0_qshares2[j])%firreducible
        temp = poly_mod_prime(temp, q_list[j])
        d0_qshares.append(temp)

    for j in range(level+1):
        temp = (c0_qshares1[j]*c1_qshares2[0][j] + c1_qshares1[0][j]*c0_qshares2[j])%firreducible;
        temp = poly_mod_prime(temp, q_list[j])
        d10_qshares.append(temp)

    for j in range(level+1):
        temp = (c0_qshares1[j]*c1_qshares2[1][j] + c1_qshares1[1][j]*c0_qshares2[j])%firreducible;
        temp = poly_mod_prime(temp, q_list[j])
        d11_qshares.append(temp)

    for j in range(level+1):
        temp = (c1_qshares1[0][j]*c1_qshares2[0][j])%firreducible;
        temp = poly_mod_prime(temp, q_list[j])
        d20_qshares.append(temp)

    for j in range(level+1):
        temp = (c1_qshares1[1][j]*c1_qshares2[1][j])%firreducible;
        temp = poly_mod_prime(temp, q_list[j])
        d21_qshares.append(temp)

    for j in range(level+1):
        temp = (c1_qshares1[0][j]*c1_qshares2[1][j] + c1_qshares1[1][j]*c1_qshares2[0][j])%firreducible;
        temp = poly_mod_prime(temp, q_list[j])
        d3_qshares.append(temp)

    d1_qshares = [d10_qshares, d11_qshares]

    d2_qshares = [d20_qshares, d21_qshares]
    non_linearized_ciphertext = [d0_qshares, d1_qshares, d2_qshares, d3_qshares]

    return non_linearized_ciphertext


#Auxiliary function: EXTENDED DECRYPTION

def extended_decryption(extended_ciphertext, key, level1, level2):

    d0 = extended_ciphertext[0];

    d1 = extended_ciphertext[1];

    d2 = extended_ciphertext[2];

    d3 = extended_ciphertext[3];

    s = key[0];

    s0 = s[0,0];

    s1 = s[0,1];

    if (level2 > level1):
        print ('ERROR:level1 must be >= level2')
        exit()

    if (level1 > level2):
        d0_q_shares = rescaling_ciphertext(d0, level1, level2)

        d10_q_shares = rescaling_ciphertext(d1[0], level1, level2)

        d11_q_shares = rescaling_ciphertext(d1[1], level1, level2)

        d20_q_shares = rescaling_ciphertext(d2[0], level1, level2)

        d21_q_shares = rescaling_ciphertext(d2[1], level1, level2)

        d3_q_shares = rescaling_ciphertext(d3, level1, level2)

    if (level1 == level2):
        d0_q_shares = d0

        d10_q_shares = d1[0]

        d11_q_shares = d1[1]

        d20_q_shares = d2[0]

        d21_q_shares = d2[1]

        d3_q_shares = d3


    temp_ed = (d0_q_shares[0] + d10_q_shares[0]*s0 + d11_q_shares[0]*s1+d21_q_shares[0]*s1*s1+d20_q_shares[0]*s0*s0+d3_q_shares[0]*s0*s1)%firreducible;

    ext_dec = poly_mod_prime(temp_ed, q_list[0]);
    print("ext_dec=", ext_dec);
    extdec_coeff = ext_dec.coefficients()

    extdec_mm1 = float(extdec_coeff[0]/(p_enc))
    print("mm1=", extdec_mm1);
    print("Original_mm1=", m_plain1*m_plain2)

