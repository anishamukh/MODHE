# ModHE
A module-LWE based homomorphic encryption scheme variant of RNS-CKKS/HEAAN.

## Proof-of-concept implementation
We give a proof-of-concept Sage implementation of the important ModHE algorithms for a module of rank two.

## Implementation using OpenFHE
We have also integrated ModHE sub-routines in OpenFHE. 

## Description
We built the ModCKKS algorithms based on the ring CKKS variant. For two elements **x** = (x_0, ..., x_(m-1))  and **y**= (y_0, ..., y_(m-1))  in a module R_q^m, operations between them boil down to lower-level operations between their respective components (x_i) and (y_i) in the underlying ring. 

## How to build/run in SageMath
Different subroutines have been added as separate files with .sage extension, for example, the key generation sub-routine is under the file name *KeyGen.sage*. The file *example.sage* runs all the sub-routines for two plaintext messages (real numbers).
1. In order to run the entire scheme in a Jupyter notebook using a SageMath kernel, simply run the command, *load("example.sage")* in the notebook.
2. In order to run selected subroutines of the scheme in a Jupyter notebook using SageMath,  comment out the excess file names from the first 6 lines of *example.sage* following this order: *constants.sage, auxiliary_functions.sage, KeyGen.sage, Encrypt-Decrypt.sage, HMult.sage, Relin.sage*. For e.g., testing a simple encryption-decryption requires the files *constants.sage, auxiliary_functions.sage, KeyGen.sage, Encrypt-Decrypt.sage*, so *HMult.sage, Relin.sage* can be commented out.
**Note:** An online SageMath compiler, such as, https://sagecell.sagemath.org/, would tolerate parameter sizes upto N = 2^8 (change it in the parameter *POLDEG* in *constants.sage*) but might not run for higher parameters.

## How to build/run in OpenFHE

The README for the OpenFHE implementation can be found [here](openfhe-development/README.md).

## Acknowledgements

We express our gratitude towards Matthias Bergmann for contributing and integrating ModHE subroutines in OpenFHE. 
