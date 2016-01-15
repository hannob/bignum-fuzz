/* point-fuzz
 *
 * Fuzzing elliptic curve scalar multiplications in OpenSSL, Nettle and NSS
 *
 * To use this preferrably compile a static version of OpenSSL and either Nettle or libmpi/libecl from NSS
 * with american fuzzy lop and link them together with this code.
 * The defines below decide which curve and which implementation you test.
 * (OpenSSL is always enabled, because we need the compressed point setting function.)
 *
 * ECC implementation notes:
 * NSS only implements NISTP256, NISTP384, NISTP521, no NISTP224
 *
 * Author: Hanno Böck
 * License: CC0 / public domain
 */

#define NETTLE
//#define NSS

#define NISTP256

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>

#ifdef NSS
#define MP_IOFUNC 1
#include "mpi.h"
#include "ecl.h"
#endif

#define MAXLEN 500

#ifdef NISTP256
#define CURVEID_OPENSSL NID_X9_62_prime256v1
#define CURVEID_NETTLE nettle_secp_256r1
#define CURVEID_NSS ECCurve_NIST_P256
#define XLEN 32
#endif

#ifdef NISTP521
#define CURVEID_OPENSSL NID_secp521r1
#define CURVEID_NETTLE nettle_secp_521r1
#define CURVEID_NSS ECCurve_NIST_P521
#define XLEN 65
#endif

#ifdef NISTP384
#define CURVEID_OPENSSL NID_secp384r1
#define CURVEID_NETTLE nettle_secp_384r1
#define CURVEID_NSS ECCurve_NIST_P384
#define XLEN 48
#endif

#ifdef NISTP224
#define CURVEID_OPENSSL NID_secp224r1
#define CURVEID_NETTLE nettle_secp_224r1
#define CURVEID_NSS ECCurve_NIST_P224
#define XLEN 28
#endif

/* Removes leading "+" sign and all leading "0" (except 1 if the result is "0"). */
char *unify_result(char *in)
{
	size_t i = 0;

	if (in[i] == '+')
		i++;

	while ((in[i] == '0') && (in[i + 1] != 0))
		i++;

	return &in[i];
}

int main(int argc, char *argv[])
{
	size_t len;
	unsigned char in[MAXLEN];
	int ret;

	EC_GROUP *curve = EC_GROUP_new_by_curve_name(CURVEID_OPENSSL);
	EC_POINT *p1 = EC_POINT_new(curve);
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *scal = BN_new();
	BIGNUM *x_ = BN_new();
	BIGNUM *y_ = BN_new();
	char *opensslx, *openssly;
	char *hx, *hy, *hs;

#ifdef NETTLE
	mpz_t nx, ny, nscal;
	struct ecc_point gp1;
	struct ecc_scalar gs1;
	char *nettlex, *nettley;
#endif

#ifdef NSS
	/* using prefix m (like mozilla), because n is already taken by nettle) */
	ECGroup *mcurve = ECGroup_fromName(CURVEID_NSS);
	mp_int mx, my, ms;
	size_t bufsize;
	char *nssx, *nssy;
#endif

	if (argc != 2) {
		printf("no file given\n");
		return -1;
	}
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		printf("can't open file\n");
		return -1;
	}

	len = fread(in, sizeof(char), MAXLEN, f);
	if (len <= (XLEN + 2))
		return -1;
	fclose(f);

	BN_bin2bn(&in[1], XLEN, x);
	BN_bin2bn(&in[XLEN], len - XLEN - 1, scal);
	ret =
	    EC_POINT_set_compressed_coordinates_GFp(curve, p1, x, in[0] & 1,
						    ctx);
	if (ret != 1) {
		printf("error creating point\n");
		return -2;
	}

	ret = EC_POINT_is_on_curve(curve, p1, ctx);
	if (ret != 1) {
		printf("point not on curve\n");
		return -3;
	}

	EC_POINT_get_affine_coordinates_GFp(curve, p1, x, y, ctx);

	EC_POINT_mul(curve, p1, 0, p1, scal, ctx);

	EC_POINT_get_affine_coordinates_GFp(curve, p1, x_, y_, ctx);

	opensslx = BN_bn2hex(x_);
	openssly = BN_bn2hex(y_);

	hx = BN_bn2hex(x);
	hy = BN_bn2hex(y);
	hs = BN_bn2hex(scal);

	BN_free(x);
	BN_free(y);
	BN_free(x_);
	BN_free(y_);
	BN_free(scal);
	EC_POINT_free(p1);
	EC_GROUP_free(curve);
	BN_CTX_free(ctx);

	printf("Input (x, y, scalar):\n%s\n%s\n%s\n\n", hx, hy, hs);
	printf("OpenSSL:\n%s\n%s\n\n", opensslx, openssly);

#ifdef NETTLE
	mpz_init_set_str(nx, hx, 16);
	mpz_init_set_str(ny, hy, 16);
	mpz_init_set_str(nscal, hs, 16);

	ecc_point_init(&gp1, &CURVEID_NETTLE);
	assert(ecc_point_set(&gp1, nx, ny) != 0);

	ecc_scalar_init(&gs1, &CURVEID_NETTLE);
	ret = ecc_scalar_set(&gs1, nscal);
	if (ret == 0) {
		printf("scalar out of range\n");
		return -1;
	}
	/* scalar out of range */
	ecc_point_mul(&gp1, &gs1, &gp1);

	ecc_point_get(&gp1, nx, ny);

	gmp_asprintf(&nettlex, "%ZX", nx);
	gmp_asprintf(&nettley, "%ZX", ny);

	printf("Nettle:\n%s\n%s\n", nettlex, nettley);
	assert(strcmp(nettlex, unify_result(opensslx)) == 0);
	assert(strcmp(nettley, unify_result(openssly)) == 0);

	mpz_clears(nx, ny, nscal, NULL);
	ecc_point_clear(&gp1);
	ecc_scalar_clear(&gs1);
	free(nettlex);
	free(nettley);
#endif

#ifdef NSS
	mp_init(&mx);
	mp_init(&my);
	mp_init(&ms);
	mp_read_radix(&mx, hx, 16);
	mp_read_radix(&my, hy, 16);
	mp_read_radix(&ms, hs, 16);

	ret = ECPoint_validate(mcurve, &mx, &my);
	if (ret == MP_NO) {
		printf("nss: point invalid\n");
		return -3;
	}

	ECPoint_mul(mcurve, &ms, &mx, &my, &mx, &my);

	f = open_memstream(&nssx, &bufsize);
	mp_print(&mx, f);
	fclose(f);
	f = open_memstream(&nssy, &bufsize);
	mp_print(&my, f);
	fclose(f);

	mp_clear(&mx);
	mp_clear(&my);
	mp_clear(&ms);
	ECGroup_free(mcurve);

	printf("nss:\n%s\n%s\n", nssx, nssy);

	assert(strcmp(unify_result(nssx), unify_result(opensslx)) == 0);
	assert(strcmp(unify_result(nssy), unify_result(openssly)) == 0);

	free(nssx);
	free(nssy);
#endif

	free(opensslx);
	free(openssly);
	free(hx);
	free(hy);
	free(hs);

	return 0;
}
