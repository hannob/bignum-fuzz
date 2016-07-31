/* Fuzz-compare the OpenSSL function BN_mod_exp() and the matrixssl function pstm_exptmod().
 *
 * To use this you should compile both matrixssl and openssl with american fuzzy lop and then statically link everything together, e.g.:
 * afl-clang-fast -o [output] [input] libgcrypto.a libcrypt_s.a libcore_s.a -I[path_to_matrixssl]
 *
 * Input is a binary file, the first bytes will decide how the rest of the file will be split into three bignums.
 *
 * by Hanno Böck, license CC0 (public domain)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>
#include <crypto/cryptoApi.h>

#define MAXBUF 1000000

struct big_results {
	char *name;
	char *a;
	char *b;
	char *c;
	char *exptmod;
};

void printres(struct big_results *res)
{
	printf("\n%s:\n", res->name);
	printf("a: %s\n", res->a);
	printf("b: %s\n", res->b);
	printf("c: %s\n", res->c);
	printf("b^c mod a: %s\n", res->exptmod);
}

void freeres(struct big_results *res)
{
	free(res->a);
	free(res->b);
	free(res->c);
	free(res->exptmod);
}

/* test bn functions from openssl/libcrypto */
void bntest(unsigned char *a_raw, int a_len, unsigned char *b_raw, int b_len,
	    unsigned char *c_raw, int c_len, struct big_results *res)
{
	BN_CTX *bctx = BN_CTX_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *res1 = BN_new();

	BN_bin2bn(a_raw, a_len, a);
	BN_bin2bn(b_raw, b_len, b);
	BN_bin2bn(c_raw, c_len, c);

	res->a = BN_bn2hex(a);
	res->b = BN_bn2hex(b);
	res->c = BN_bn2hex(c);

	BN_mod_exp(res1, b, c, a, bctx);
	res->exptmod = BN_bn2hex(res1);

	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(res1);
	BN_CTX_free(bctx);
}

int matrixtest(unsigned char *a_raw, int a_len, unsigned char *b_raw, int b_len,
	       unsigned char *c_raw, int c_len, struct big_results *res)
{
	psPool_t *pool = NULL;
	unsigned char *rr = malloc(4096);
	char *buf, *buf_ptr;
	int i, s;
	pstm_int a, b, c, r;
	psCryptoOpen("YYYYNNNYYNN");

	if (pstm_init_for_read_unsigned_bin(pool, &a, a_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin a error\n");
		return -1;
	}
	if (pstm_read_unsigned_bin(&a, a_raw, a_len) != 0) {
		printf("pstm_read_unsigned_bin a error\n");
		return -1;
	}
	if (pstm_init_for_read_unsigned_bin(pool, &b, b_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin b error\n");
		return -1;
	}
	if (pstm_read_unsigned_bin(&b, b_raw, b_len) != 0) {
		printf("pstm_read_unsigned_bin b error\n");
		return -1;
	}
	if (pstm_init_for_read_unsigned_bin(pool, &c, c_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin c error\n");
		return -1;
	}
	if (pstm_read_unsigned_bin(&c, c_raw, c_len) != 0) {
		printf("pstm_read_unsigned_bin c error\n");
		return -1;
	}

	if (pstm_init(pool, &r) != 0) {
		printf("pstm_init r error\n");
		return -1;
	}

	if (pstm_exptmod(pool, &b, &c, &a, &r) != 0) {
		printf("pstm_exptmod error\n");
		return -1;
	}

	if (pstm_to_unsigned_bin(0, &r, rr) < 0) {
		printf("pstm_to_unsigned_bin error\n");
		return -1;
	}
	s = pstm_unsigned_bin_size(&r);
	buf = buf_ptr = malloc(s * 2 + 1);
	for (i = 0; i < s; i++) {
		buf_ptr += sprintf(buf_ptr, "%02X", rr[i]);
	}

	res->exptmod = buf;

/*	printf("matrixssl: %s\n", buf);*/
	return 0;
}

int main(int argc, char *argv[])
{
	size_t len, l1, l2, l3;
	unsigned int divi1, divi2;
	unsigned char in[MAXBUF];
	unsigned char *a, *b, *c;
	struct big_results openssl_results = { "openssl", 0, 0, 0, 0 };
	struct big_results gcrypt_results = { "libgcrypt", 0, 0, 0, 0 };
	struct big_results matrix_results = { "libgcrypt", 0, 0, 0, 0 };
	int i;

	if (argc != 2) {
		printf("no file given\n");
		return -1;
	}
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		printf("can't open file\n");
		return -1;
	}

	len = fread(in, sizeof(char), MAXBUF, f);
	if (len < 5)
		return -1;
	fclose(f);

	divi1 = in[0];
	divi2 = in[1];
	divi1++;
	divi2++;
	l1 = (len - 2) * divi1 / 256;
	l2 = (len - 2 - l1) * divi2 / 256;
	l3 = (len - 2 - l1 - l2);
	assert(l1 + l2 + l3 == len - 2);
#ifdef VERBOSE
	printf("div1 div2 %i %i\n", divi1, divi2);
	printf("len l1 l2 l3 %i %i %i %i\n", (int)len, (int)l1, (int)l2,
	       (int)l3);
#endif
	a = in + 2;
	b = in + 2 + l1;
	c = in + 2 + l1 + l2;

	if ((l1 == 0) || (l2 == 0) || (l3 == 0))
		return 2;

#ifdef VERBOSE
	printf("a: \n");
	for (i = 0; i < l1; i++)
		printf("%02x:", a[i]);
	printf("\nb: \n");
	for (i = 0; i < l2; i++)
		printf("%02x:", b[i]);
	printf("\nc: \n");
	for (i = 0; i < l3; i++)
		printf("%02x:", c[i]);
	printf("\n");
#endif

	if (matrixtest(a, l1, b, l2, c, l3, &matrix_results) ) {
		printf("error from matrixssl, probably invalid input\n");
		return 1;
	}


	bntest(a, l1, b, l2, c, l3, &openssl_results);
	printres(&openssl_results);

	if (strcmp(openssl_results.b, "0")==0) {
		printf("zero base\n");
		return 1;
	}

	assert(strcmp(openssl_results.exptmod, matrix_results.exptmod)
	       == 0);

	freeres(&openssl_results);
	freeres(&gcrypt_results);

	return 0;
}
