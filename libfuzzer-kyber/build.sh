#!/bin/bash

if [ "$1" = "fetch" ]; then
	git clone --depth=1 https://github.com/pq-crystals/kyber.git
	sed -e 's:polyvec_:ref_polyvec_:g' -e 's:poly_:ref_poly_:g'  \
		-e 's:omegas_:ref_omegas_:g' \
		-e 's:indcpa_:ref_indcpa_:g' \
		-e 's:crypto_:ref_crypto_:g' \
		-e 's:kyber_:ref_kyber_:g' \
		-e 's:psis_:ref_psis_:g' \
		-e 's:montgomery_reduce:ref_montgomery_reduce:g' \
		-e 's:barrett_reduce:ref_barrett_reduce:g' \
		-e 's:freeze:ref_freeze:g' \
		-e 's:gen_matrix:ref_gen_matrix:g' \
		-e 's: pack_: ref_pack_:g' \
		-e 's: unpack_: ref_unpack_:g' \
		-e 's:shake:ref_shake:g' \
		-e 's:keccak:ref_keccak:g' \
		-e 's:Keccak:ref_Keccak:g' \
		-e 's:sha3:ref_sha3:g' \
		-e 's:verify(:ref_verify\(:g' \
		-e 's: ntt(: ref_ntt\(:g' \
		-e 's: invntt(: ref_invntt\(:g' \
		-e 's: cbd(: ref_cbd\(:g' \
		-e 's: cmov(: ref_cmov\(:g' \
		-e 's: load64(: ref_load64(:g' \
		-e 's: store64(: ref_store64(:g' \
		-e 's: randombytes(: ref_randombytes(:g' \
		-e 's: cpucycles(: ref_cpucycles(:g' \
		kyber/ref/*.c kyber/ref/*.h -i
fi

CFLAGS="-march=native -fsanitize=address -fsanitize-coverage=trace-pc-guard"

pushd kyber/ref
clang $CFLAGS -c cbd.c cpucycles.c fips202.c indcpa.c kem.c kex.c ntt.c poly.c polyvec.c precomp.c randombytes.c reduce.c verify.c
popd

pushd kyber/avx2
clang $CFLAGS -c cbdref.c consts.c cpucycles.c fips202.c fips202x4.c genmatrix.c indcpa.c keccak4x/KeccakP-1600-times4-SIMD256.c kem.c kex.c poly.c polyvec.c precomp.c randombytes.c reduce.c verify.c
popd

clang -fsanitize-coverage=trace-pc-guard -fsanitize=address libfuzzer-kyber.c  -c
clang++ libfuzzer-kyber.o kyber/*/*.o libFuzzer.a -fsanitize=address -fsanitize-coverage=trace-pc-guard kyber/*/*.s -o libfuzzer-kyber
