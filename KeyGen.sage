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