# ModHE
A module-LWE based homomorphic encryption scheme variant of RNS-CKKS/HEAAN.

## Proof-of-concept implementation
We give a proof-of-concept Sage implementation of the important ModCKKS algorithms for a module of rank two.

## Description
We built the ModCKKS algorithms based on the ring CKKS variant. For two elements **x** = (x_0, ..., x_(m-1))  and **y**= (y_0, ..., y_(m-1))  in a module R_q^m, operations between them boil down to lower-level operations between their respective components (x_i) and (y_i) in the underlying ring. 

## How to build/run
Different subroutines have been added as separate files with .sage extension, for example, the key generation sub-routine is under the file name *KeyGen.sage*. The file *example.sage* runs all the sub-routines for two plaintext messages (real numbers).
1. In order to run the entire scheme in a Jupyter notebook using a SageMath kernel, un-comment the first 6 lines of *example.sage* to include all files describing the sub-routines of the scheme, and then simply run *load("example.sage")* in the notebook.
2. In order to run selected subroutines of the scheme in a jupyter notebook using SageMath,  un-comment the required file names from the first 6 lines of *example.sage* following this order until the scheme sub-routine you want to run : *constants.sage, auxiliary_functions.sage, KeyGen.sage, Encrypt-Decrypt.sage, HMult.sage, Relin.sage, example.sage*. For e.g., testing a simple encryption-decryption requires the files *constants.sage, auxiliary_functions.sage, KeyGen.sage, Encrypt-Decrypt.sage*.
This unoptimized POC version takes about an hour and a half for a ring of dimension N = 2^14 (it is set to 2^14 in the *POLDEG* variable in *constants.sage*) and module of rank 2, when run on Ubuntu 18.04 with 16GB RAM and 64-bit Intel Core i7-10750H CPU@2.60GHz x 12 processor using SageMath.10.3.
**Note:** An online SageMath compiler, such as, https://sagecell.sagemath.org/, would tolerate parameter sizes upto N = 2^8 (change it in the parameter *POLDEG* in *constants.sage*) but might not run for higher parameters.

