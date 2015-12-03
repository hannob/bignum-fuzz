# bignum-fuzz
Code to fuzz bignum libraries


 CVE-2015-3193-openssl-vs-gcrypt-modexp.c

This is a simple test that will do a calculation that some versions of OpenSSL will get wrong and compare the result with libgcrypt.


 openssl-vs-gcrypt-modexp.c

This is a sample code to fuzz the BN_mod_exp() function of OpenSSL and the gcry_mpi_powm() function of libgcrypt.


Usage instructions are in the code.