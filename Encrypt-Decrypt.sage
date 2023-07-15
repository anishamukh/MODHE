#function for ENCRYPTION
def encryption(m_plain, key):

	# print 'encryption'
	# Step1: generate error poly e0
    e0=matrix(R,1,MLWE);
    for k in range(MLWE):
        e_k = 0;
        for i in range(POLDEG):
            coeff = random_between(0,Berr)
            e_k = e_k + coeff*x^i;
        e0[0,k]=e_k

	# Step2: generate error poly e1
    e1=matrix(R,1,MLWE);
    for k in range(MLWE):
        e_k = 0;
        for i in range(POLDEG):
            coeff = random_between(0,Berr)
            e_k = e_k + coeff*x^i;
        e1[0,k]=e_k

	# Step3: generate sparse binary poly v
    v=matrix(R,1,MLWE);
    for k in range(MLWE):
        v_k = 0;
        for i in range(POLDEG):
            coeff = random_between(0,1)*random_between(0,1)
            v_k = v_k + coeff*x^i;
        v[0,k]=v_k



	# Note that ciphertext ct(j) ← v·pk(j) + (m + e0, e1)

	# Step4: encode single
    m_enc = round(m_plain*p_enc);
    print("m=", m_plain)

    c0_q = matrix(R,1, 1)
    c1_q = matrix(R,1, MLWE)

    b_pk = key[1]
    A = key[2]

    temp = (v*b_pk + m_enc + e0[0,0])%firreducible;
    temp = poly_mod_prime(temp[0,0], Q);
    c0_q[0,0] = temp

    temp = (v*A + e1)%firreducible;
    c1_q[0,0] = poly_mod_prime(temp[0,0], Q);
    c1_q[0,1] = poly_mod_prime(temp[0,1], Q);

    #shares of the ciphertext in Q
    c0_qshares = shares_in_mod(c0_q[0,0], L, q_list)
    c10_qshares = shares_in_mod(c1_q[0,0], L, q_list)
    c11_qshares = shares_in_mod(c1_q[0,1], L, q_list)

    c1_qshares = [c10_qshares, c11_qshares]

    ciphertext = [c0_qshares, c1_qshares]

    return ciphertext

#function for DECRYPTION
def decryption(ct, key, level1, level2):

    print("decryption:")
    c0_q = ct[0]

    c1_q = ct[1]

    s = key[0]
    s0 = s[0,0]
    s1 = s[0,1]

    if (level2 > level1):

        exit()

    if (level1 > level2):
        c0_dec_q_shares = rescaling_ciphertext(c0_q, level1, level2)
        c10_dec_q_shares = rescaling_ciphertext(c1_q[0], level1, level2)
        c11_dec_q_shares = rescaling_ciphertext(c1_q[1], level1, level2)

    if (level1 == level2):
        c0_dec_q_shares = c0_q
        c10_dec_q_shares = c1_q[0]
        c11_dec_q_shares = c1_q[1]

    temp1 = (c10_dec_q_shares[0]*s0)%firreducible 
    temp2 = (c11_dec_q_shares[0]*s1)%firreducible

    temp = (c0_dec_q_shares[0][0] + temp1 + temp2)%firreducible;

    dec = poly_mod_prime(temp[0][0], q_list[0]);

    dec_coeff = dec.coefficients()

    dec_m = float(dec_coeff[0]/p_enc)
    return dec_m
