libfuzzer-kyber
===============

libfuzzer stub for the kyber post quantum kem algorithm.

description
===========

The stub code will run the indcpa_enc function of kyber both with the reference and the avx2
implementation and will compare the result. It will throw an assert if they don't match.

usage
=====

Run:
  ./build.sh fetch

It will fetch kyber from github, get libFuzzer.a and create a fuzzer stub libfuzzer-kyber.
All functions in the reference implementation of kyber will be prefixed with ref_.

If you want to rebuild without re-fetching kyber and libFuzzer just run:
  ./build.sh
