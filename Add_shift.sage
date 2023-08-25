L=2; MLWE=2;
q_list = vector((576460752304439297, 9007199255560193)) #q0 = 2**59 + 31*(2**15) + 1 = 2**59 + (2**20) - (2**15) + 1, q1 = 2**53 + 25*(2**15) + 1 = 2**53 + (2**19) + (2**18) + (2**15) + 1
p = 9007199379521537;
p_enc = 9007199254740992; #2^53


moduli = []
for i in range(L):
	moduli.append(q_list[i])
moduli.append(p)

Q=1;
for i in range(L):
	Q = Q*q_list[i];

p_inv_q = [0]*L
for j in range(L):
	p_inv_q[j] = p^(-1) % q_list[j]



POLDEG=2^2;

Berr=10;

R.<x> = QQ[];
firreducible = x^POLDEG + 1;

# START: Constants for ModUP() and ModDown()
q_hat = [0]*L
q_hat_inv = [0]*L
B = [0]*L

for j in range(L):
	q_hat[j] = Q/q_list[j]
	q_hat_inv[j] = q_hat[j]^(-1) % q_list[j]
	B[j] = q_hat_inv[j]*q_hat[j]

def random_between(j,k) :
        a=int(random()*(k-j+1))+j
        return a

#add_shift for q0
def q0_first_step_red(a,q0):

    a_h = (a >> 59)
    a_l = (a % 2**59)

    r = (a_h << 20) + a_h
    r2= (a_h << 15) + a_l

    b = r2 - r
    
    b = b + (q0 << 21)
    
    return b

def q0_second_step_red(a,q0):
        
    a_h = (a >> 59)
    a_l = (a % 2**59)

    r = (a_h << 20) + a_h
    r2= (a_h << 15) + a_l
    
    b = r2 - r
    
    return b


#add_shift for q1
def q1_first_step_red(a,q1):
        
    a_h = (a >> 53)
    a_l = (a % 2**53)

    r = (a_h << 19) + (a_h << 18) + (a_h << 15) + a_h
    r2= a_l
    
    b = r2 - r
    
    b = b + (q1 << 20)

    
    return b

def q1_second_step_red(a,q1):
   
    
    a_h = (a >> 53)
    a_l = (a % 2**53)

    r = (a_h << 19) + (a_h << 18) + (a_h << 15) + a_h
    r2= a_l
    
    b = r2 - r
    
    return b

#add_shift final
def add_shift(d, q):
    if(q==576460752304439297):
        c = q0_first_step_red(d,q)
        c = q0_second_step_red(c,q)

        if c < 0:
            c = c+q

    elif(q==9007199255560193):
        c = q1_first_step_red(d,q)
        c = q1_second_step_red(c,q)

        if c < 0:
            c = c+q
        
    
    return int(c)


def poly_mod_prime(pol_a, mod) :
    L = list(pol_a)
    pol_b = 0;
    for i in range(len(L)):
        if(mod==576460752304439297 or mod==9007199255560193):
            coeff = add_shift(int(L[i]), mod)
        else:
            coeff = int(L[i])%mod
        pol_b = pol_b+coeff*x^i	
    return(pol_b)
#function to evaluate shares
def shares_in_mod(poly_mat, size, list):
    poly_shares = [];
    for i in range (size):
        poly_shares.append(poly_mod_prime(poly_mat, list[i]))
    return poly_shares

#function for rescaling
def rescaling_shares(coeff_shares, level_in, level_out):
	coeff_shares_scaled = copy(coeff_shares)

	for l in range(level_in, level_out, -1):
		for j in range(l):
			temp = (q_list[l]^-1)%q_list[j]
			coeff_shares_scaled[j] =  temp*(coeff_shares_scaled[j] - coeff_shares_scaled[l]) % q_list[j]
		coeff_shares_scaled[l] = 0

	return coeff_shares_scaled

def rescaling_ciphertext(ct_shares, level_in, level_out):
	ct_scaled_shares = []

	for j in range(level_out+1):
		ct_scaled_shares.append(0)

	for i in range(POLDEG):
		
		in_shares = []

		for j in range(level_in+1):
			temp = int(ct_shares[j].coefficients(sparse=False)[i])
			in_shares.append(temp)

		out_shares = rescaling_shares(in_shares, level_in, level_out)

		for j in range(level_out+1):
			ct_scaled_shares[j] = ct_scaled_shares[j] + int(out_shares[j])*x^i
	
	return ct_scaled_shares 
 
#function to generate PUBLIC KEY

def public_private_keygen():

    #Generation of secret polynomial vector s=[s0, s1, ...]
    s = matrix(R, 1, MLWE);
    for k in range(MLWE):
        s_k=0;
        for i in range(POLDEG-1): 
            coeff = random_between(0,1)
            s_k = s_k + coeff*x^i;
        s_k = s_k + x^(POLDEG-1);
        s[0,k] = s_k

    #Generation of error polynomial vector e=[e0, e1, ...] for encryption
    e = matrix(R, 1, MLWE);
    for k in range(MLWE):
        e_k = 0;
        for i in range(POLDEG): 
            coeff = random_between(0,Berr)
            e_k = e_k + coeff*x^i;	
        e[0,k]=e_k

    #Generate a random matrix [A]_mlwe*mlwe
    A = matrix(R, MLWE, MLWE);        
    for l in range(MLWE):
        for k in range(MLWE):
            a_lk = 0
            for i in range(POLDEG):
                coeff = int(Q*random())
                a_lk = a_lk + coeff*x^i
            A[l, k] = a_lk

    b_pk = matrix(R, 1, MLWE)
    b_pk = -A*s.transpose() + e.transpose()
    
    # Note: sk = {1, s} and pk = {b_pk_q, a_pk_q}
    key = [s, b_pk, A]
    print('private-public keypair generated')
    
    return key

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
    print(dec_m)


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
    
    extdec_coeff = ext_dec.coefficients()

    extdec_mm1 = float(extdec_coeff[0]/(p_enc))
    print("HEmm1=", extdec_mm1);
    print("Original_mm1=", m_plain1*m_plain2)


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
    for j in range(MLWE):
        evkd20_shares.append(shares_in_mod((evkd2[j][0][0])%firreducible, L+1, moduli))
    #print("evkd20_shares", evkd20_shares)

    
    evkd21_shares = [];
    for j in range(MLWE):
        evkd21_shares.append(shares_in_mod((evkd2[j][1][0])%firreducible, L+1, moduli))
    
    #shares of evl_key of d2 
    evkd2_shares = [ evkd20_shares, evkd21_shares];
    
    #shares of the first part of evl_key of d3 
    evkd30_shares = [];
    for j in range(MLWE):
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


key = public_private_keygen()
evk_key = relin_keygen(key)
m_plain1=0.5
m_plain2=0.9
ct1=encryption(m_plain1, key)
ct2=encryption(m_plain2, key)
print(decryption(ct1, key, 0, 0))
print(decryption(ct2, key, 0, 0))
decryption(relinearisation(homomorphic_mult(ct1, ct2, 1, key), evk_key),key,1,0)
print("original_dec=", m_plain1*m_plain2)