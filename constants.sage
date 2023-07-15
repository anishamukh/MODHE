
q_list = vector((576460752340123649, 9007199282003969, 9007199284101121, 9007199318704129, 9007199338627073, 9007199343869953, 9007199350161409));
p = 9007199379521537;
p_enc = 9007199254740992;
L=7; MLWE=2;

#moduli = [q_list[0], q_list[1], q_list[2], q_list[3], q_list[4], q_list[5], p]
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


#Polynomial degree
POLDEG=2^14;


#Gaussian bound
Berr=10;

R.<x> = QQ[];
firreducible = x^POLDEG + 1;

#Constants for ModUP() and ModDown()
q_hat = [0]*L
q_hat_inv = [0]*L
B = [0]*L

for j in range(L):
	q_hat[j] = Q/q_list[j]
	q_hat_inv[j] = q_hat[j]^(-1) % q_list[j]
	B[j] = q_hat_inv[j]*q_hat[j]