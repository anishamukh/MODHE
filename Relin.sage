#function for EVALUATION KEY    
def relin_keygen(key):
    s = key[0];
    s2 = matrix([[s[0,0]*s[0,0]], [s[0,1]*s[0,1]]])
    s0s1 = matrix([[s[0,0]*s[0,1]], [s[0,0]*s[0,1]]])
    evkd2_shares = [];
    A_d2shares = [];
    A_d3shares = [];
    
    #j error polynomials for evl_key of d2
    e_evkd2 = [];
    for j in range(L):
        ed2 = matrix(R, 1, MLWE);
        for k in range(MLWE):
            e_k = 0;
            for i in range(POLDEG): 
                coeff = random_between(0,Berr)
                e_k = e_k + coeff*x^i;	
            ed2[0,k]=e_k
        e_evkd2.append(ed2)
    
    #j error polynomials for evl_key of d3 
    e_evkd3 = [];
    for j in range(L):
        ed3 = matrix(R, 1, MLWE);
        for k in range(MLWE):
            e_k = 0;
            for i in range(POLDEG): 
                coeff = random_between(0,Berr)
                e_k = e_k + coeff*x^i;	
            ed3[0,k]=e_k
        e_evkd3.append(ed3)
    
    #j public matrices for evl_key of d2 (so j copies of 2x2 matrix)
    A_evkd2 = [];
    for j in range(L):
        A_d2 = matrix(R, MLWE, MLWE);        
        for l in range(MLWE):
            for k in range(MLWE):
                a_lk = 0
                for i in range(POLDEG):
                    coeff = int(p*Q*random())
                    a_lk = a_lk + coeff*x^i
                A_d2[l, k] = a_lk
        A_evkd2.append(A_d2)
    #print("A_evkd2", A_evkd2[1])
    
    
    #shares of each component of the public key (so i shares of each of the j matrix component [A1]_00, [A2]_00,..., [Aj]_00) and so on for the next components
    A_evkd200shares = [];
    for j in range(L):
        A_evkd200shares.append(shares_in_mod(A_evkd2[j][0][0], L+1, moduli))
    
    A_evkd201shares = []
    for j in range(L):
        A_evkd201shares.append(shares_in_mod(A_evkd2[j][0][1], L+1, moduli))

    A_evkd210shares = []
    for j in range(L):
        A_evkd210shares.append(shares_in_mod(A_evkd2[j][1][0], L+1, moduli))

    A_evkd211shares = []
    for j in range(L):
        A_evkd211shares.append(shares_in_mod(A_evkd2[j][1][1], L+1, moduli))
    
    
    A_d2shares = [A_evkd200shares, A_evkd201shares, A_evkd210shares, A_evkd211shares]
    
    #same for j copies of 2x2 matrix of evl_key of d3
    A_evkd3 = []; 
    for j in range(L):
        A_d3 = matrix(R, MLWE, MLWE);        
        for l in range(MLWE):
            for k in range(MLWE):
                a_lk = 0
                for i in range(POLDEG):
                    coeff = int(p*Q*random())
                    a_lk = a_lk + coeff*x^i
                A_d3[l, k] = a_lk
        A_evkd3.append(A_d3)
    A_evkd300shares = []
    for j in range(L):
        A_evkd300shares.append(shares_in_mod(A_evkd3[j][0][0], L+1, moduli))

    A_evkd301shares = []
    for j in range(L):
        A_evkd301shares.append(shares_in_mod(A_evkd3[j][0][1], L+1, moduli))

    A_d3shares = [A_evkd300shares, A_evkd301shares]   
    
    evkd2 = [];
    for j in range(L):
        evk_d2 = matrix(R, 1, MLWE)
        evk_d2 = -A_evkd2[j]*s.transpose() + p*B[j]*s2 + e_evkd2[j].transpose()
        evkd2.append(evk_d2)
    
    evkd3 = [];
    for j in range(L):
        evk_d3 = matrix(R, 1, MLWE)
        evk_d3 = -A_evkd3[j]*s.transpose() + p*B[j]*s0s1 + e_evkd3[j].transpose()
        evkd3.append(evk_d3)
        
    evkd20_shares = [];
    for j in range(L):
        evkd20_shares.append(shares_in_mod((evkd2[j][0][0])%firreducible, L+1, moduli))
    #print("evkd20_shares", evkd20_shares)

    
    evkd21_shares = [];
    for j in range(L):
        evkd21_shares.append(shares_in_mod((evkd2[j][1][0])%firreducible, L+1, moduli))
    
    #shares of evl_key of d2 
    evkd2_shares = [ evkd20_shares, evkd21_shares];
    
    #shares of the first part of evl_key of d3 
    evkd30_shares = [];
    for j in range(L):
        evkd30_shares.append(shares_in_mod((evkd3[j][0][0])%firreducible, L+1, moduli))
    
    evk_key = [evkd2_shares, A_d2shares, evkd30_shares, A_d3shares]
    
    return evk_key

#function for changing modulus (MOD DOWN)
def ModDown(b_share_p, b_shares_q):

	a_shares_q = [0]*L

	result_q = [0]*L



	#Base conversion from B to C

	for i in range(L):

		a_shares_q[i] = b_share_p % q_list[i]



		result_q[i] = p_inv_q[i]*(b_shares_q[i] - a_shares_q[i]) % q_list[i]



	return result_q


#function for RELINEARISATION
def relinearisation (non_linearized_ciphertext, evk_key):

    d0_qshares = non_linearized_ciphertext[0]

    d1_qshares = non_linearized_ciphertext[1]
    
    d10_qshares = d1_qshares[0]

    d11_qshares = d1_qshares[1]
    
    d2_qshares = non_linearized_ciphertext[2]

    d20_qshares = d2_qshares[0]
    
    d21_qshares = d2_qshares[1]
    

    d3_qshares = non_linearized_ciphertext[3]
    
    evkd2shares = evk_key[0]
    
    evkd20_shares = evkd2shares[0]
    
    evkd21_shares = evkd2shares[1]
    
    A_d2shares = evk_key[1]
    
    A_d200shares = A_d2shares[0]
    
    A_d201shares = A_d2shares[1]
    
    A_d210shares = A_d2shares[2]
    
    A_d211shares = A_d2shares[3]
    
    evkd30shares = evk_key[2]
    
    A_d3shares = evk_key[3]
    
    A_d300shares = A_d3shares[0]
    
    A_d301shares = A_d3shares[1]
            
    #first relinearised component
    ct_0primeshares=[0]*(L+1);

    for i in range(L+1):

        ct_0primeshares[i]=0

        for j in range(L):

            temp = (d20_qshares[j]*evkd20_shares[j][i] + d3_qshares[j]*evkd30shares[j][i] + d21_qshares[j]*evkd21_shares[j][i])%firreducible
            
            temp = poly_mod_prime(temp, moduli[i])

            ct_0primeshares[i] = ct_0primeshares[i] + temp
            
        ct_0primeshares[i] = poly_mod_prime(ct_0primeshares[i], moduli[i])
    
        
    #second relinearised component
    ct_10primeshares=[0]*(L+1);

    for i in range(L+1):

        ct_10primeshares[i]=0

        for j in range(L):

            temp = (d20_qshares[j]*A_d200shares[j][i] + d3_qshares[j]*A_d300shares[j][i] + d21_qshares[j]*A_d210shares[j][i])%firreducible

            temp = poly_mod_prime(temp, moduli[i])

            ct_10primeshares[i] = ct_10primeshares[i] + temp

        ct_10primeshares[i] = poly_mod_prime(ct_10primeshares[i], moduli[i])

        
    #third relinearised component
    ct_11primeshares=[0]*(L+1);

    for i in range(L+1):

        ct_11primeshares[i]=0

        for j in range(L):

            temp = (d20_qshares[j]*A_d201shares[j][i] + d3_qshares[j]*A_d301shares[j][i] + d21_qshares[j]*A_d211shares[j][i])%firreducible

            temp = poly_mod_prime(temp, moduli[i])

            ct_11primeshares[i] = ct_11primeshares[i] + temp

        ct_11primeshares[i] = poly_mod_prime(ct_11primeshares[i], moduli[i])

            
    #scaling down
    ct_0primeshares_scaled_q_shares=[0]*L

    for i in range(POLDEG):

        shares_q=[]

        for j in range(L):

            shares_q.append(ct_0primeshares[j].coefficients(sparse=False)[i])	

        share_p = ct_0primeshares[L].coefficients(sparse=False)[i]

        scaled_shares_q = ModDown(share_p, shares_q) 

        for j in range(L):

            ct_0primeshares_scaled_q_shares[j] = ct_0primeshares_scaled_q_shares[j] + int(scaled_shares_q[j])*x^i
   

    ct_10primeshares_scaled_q_shares=[0]*L

    for i in range(POLDEG):

        shares_q=[]

        for j in range(L):

            shares_q.append(ct_10primeshares[j].coefficients(sparse=False)[i])	

        share_p = ct_10primeshares[L].coefficients(sparse=False)[i]

        scaled_shares_q = ModDown(share_p, shares_q) 

        for j in range(L):

            ct_10primeshares_scaled_q_shares[j] = ct_10primeshares_scaled_q_shares[j] + int(scaled_shares_q[j])*x^i

    
    ct_11primeshares_scaled_q_shares=[0]*L

    for i in range(POLDEG):

        shares_q=[]

        for j in range(L):

            shares_q.append(ct_11primeshares[j].coefficients(sparse=False)[i])	

        share_p = ct_11primeshares[L].coefficients(sparse=False)[i]

        scaled_shares_q = ModDown(share_p, shares_q)

        for j in range(L):

            ct_11primeshares_scaled_q_shares[j] = ct_11primeshares_scaled_q_shares[j] + int(scaled_shares_q[j])*x^i

            
    cmult0_qshares = []

    cmult10_qshares = []

    cmult11_qshares = []
    
    cmult1_qshares = matrix(R,1, MLWE)

    #final final relinearised ciphertext [cmult0_qshares, cmult1_qshares]
    for j in range(L):

        temp = d0_qshares[j] + ct_0primeshares_scaled_q_shares[j]

        temp = poly_mod_prime(temp, q_list[j]) 

        cmult0_qshares.append(temp)



    for j in range(L):

        temp = d10_qshares[j] + ct_10primeshares_scaled_q_shares[j]

        temp = poly_mod_prime(temp, q_list[j]) 

        cmult10_qshares.append(temp)

        
    for j in range(L):

        temp = d11_qshares[j] + ct_11primeshares_scaled_q_shares[j]

        temp = poly_mod_prime(temp, q_list[j]) 

        cmult11_qshares.append(temp)

        cmult1_qshares = [cmult10_qshares, cmult11_qshares]
    linearized_ciphertext = [cmult0_qshares, cmult1_qshares]
    
    return linearized_ciphertext
