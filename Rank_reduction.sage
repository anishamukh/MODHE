# function to generate rank-reduction key

def rankred_key(key):

    s = key[0]
    s0 = s[0,0]
    s1 = s[0,1]

    e=[];
    a_rankred = []
    b_rankred = []

    #Step1: Sample e_j
    for j in range(L):
        temp = 0;
        for i in range(POLDEG): 
            coeff = random_between(0,Berr)
            temp = temp + coeff*x^i;
        e.append(temp)

    for j in range(L):
        temp = 0;
        for i in range(POLDEG): 
            coeff = int(p*Q*random())	
            temp = temp + coeff*x^i
        a_rankred.append(temp)

    #Step3: Compute b_evk_j \in (mod pQ) 
    for j in range(L):
        temp = (-a_rankred[j]*s0 + e[j] + p*B[j]*s1)%firreducible;	
        temp = poly_mod_prime(temp, p*Q)
        b_rankred.append(temp)


    a_rankred_matrix = []
    for j in range(L):
        a_rankred_j_shares = []
        for i in range(L+1):
            temp = poly_mod_prime(a_rankred[j], moduli[i])
            a_rankred_j_shares.append(temp)
        a_rankred_matrix.append(a_rankred_j_shares)		

    b_rankred_matrix = []
    for j in range(L):
        b_rankred_j_shares = []
        for i in range(L+1):
            temp = poly_mod_prime(b_rankred[j], moduli[i])
            b_rankred_j_shares.append(temp)
        b_rankred_matrix.append(b_rankred_j_shares)		

    rankred_key = [b_rankred_matrix, a_rankred_matrix]

    return rankred_key

#call this function to perform rank-reduction after the last linearisation in the specific module of rank r before moving to r'<r

def rank_red (linearized_ciphertext, rankred_key):

    ct0_qshares = linearized_ciphertext[0]

    ct1_qshares = linearized_ciphertext[1]

    ct10_qshares = ct1_qshares[0]

    ct11_qshares = ct1_qshares[1]

    rankred_key0 = rankred_key[0]

    rankred_key1 = rankred_key[1]


    #first rank-reduced component
    ct_0redshares=[0]*(L+1);

    for i in range(L+1):

        ct_0redshares[i]=0

        for j in range(L):

            temp = (ct11_qshares[j]*rankred_key0[j][i])%firreducible

            temp = poly_mod_prime(temp, moduli[i])

            ct_0redshares[i] = ct_0redshares[i] + temp

        ct_0redshares[i] = poly_mod_prime(ct_0redshares[i], moduli[i])


    #second rank-reduced component
    ct_1redshares=[0]*(L+1);

    for i in range(L+1):

        ct_1redshares[i]=0

        for j in range(L):

            temp = (ct11_qshares[j]*rankred_key1[j][i])%firreducible

            temp = poly_mod_prime(temp, moduli[i])

            ct_1redshares[i] = ct_1redshares[i] + temp

        ct_1redshares[i] = poly_mod_prime(ct_1redshares[i], moduli[i])


    #scaling down
    ct_0redshares_scaled_q_shares=[0]*L

    for i in range(POLDEG):

        shares_q=[]

        for j in range(L):

            shares_q.append(ct_0redshares[j].coefficients(sparse=False)[i])	

        share_p = ct_0redshares[L].coefficients(sparse=False)[i]

        scaled_shares_q = ModDown(share_p, shares_q) 

        for j in range(L):

            ct_0redshares_scaled_q_shares[j] = ct_0redshares_scaled_q_shares[j] + int(scaled_shares_q[j])*x^i

    ct_1redshares_scaled_q_shares=[0]*L

    for i in range(POLDEG):

        shares_q=[]

        for j in range(L):

            shares_q.append(ct_1redshares[j].coefficients(sparse=False)[i])	

        share_p = ct_1redshares[L].coefficients(sparse=False)[i]

        scaled_shares_q = ModDown(share_p, shares_q) 

        for j in range(L):

            ct_1redshares_scaled_q_shares[j] = ct_1redshares_scaled_q_shares[j] + int(scaled_shares_q[j])*x^i


    cred0_qshares = []

    cred1_qshares = []



    #final reduced ciphertext 
    for j in range(L):

        temp = ct0_qshares[j] + ct_0redshares_scaled_q_shares[j]

        temp = poly_mod_prime(temp, q_list[j]) 

        cred0_qshares.append(temp)



    for j in range(L):

        temp = ct10_qshares[j] + ct_1redshares_scaled_q_shares[j]

        temp = poly_mod_prime(temp, q_list[j]) 

        cred1_qshares.append(temp)


    rankred_ciphertext = [cred0_qshares, cred1_qshares]

    return rankred_ciphertext