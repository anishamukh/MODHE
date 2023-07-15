def random_between(j,k) :
        a=int(random()*(k-j+1))+j
        return a

def poly_mod_prime(pol_a, mod) :
    L = list(pol_a)
    pol_b = 0;
    for i in range(len(L)):
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
 