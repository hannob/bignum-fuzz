/* Testing MatrixSSL's pstm_exptmod with base == modulus
 * by Hanno Böck, license: CC0
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <crypto/cryptoApi.h>

unsigned char a1[] = {
	0xcc
};

unsigned int a1_len = 1;

unsigned char b1[] = {
	0xbb
};

unsigned int b1_len = 1;

unsigned char m1[] = {
	0xcc
};

unsigned int m1_len = 1;

char *matrixtest(unsigned char *a_raw, int a_len, unsigned char *b_raw,
		 int b_len, unsigned char *m_raw, int m_len)
{
	unsigned char *rr = malloc(4096);
	char *buf, *buf_ptr;
	int i, s;
	pstm_int a, b, m, r;

	if (pstm_init_for_read_unsigned_bin(NULL, &a, a_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin a error\n");
		return 0;
	}
	if (pstm_read_unsigned_bin(&a, a_raw, a_len) != 0) {
		printf("pstm_read_unsigned_bin a error\n");
		return 0;
	}
	if (pstm_init_for_read_unsigned_bin(NULL, &b, b_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin b error\n");
		return 0;
	}
	if (pstm_read_unsigned_bin(&b, b_raw, b_len) != 0) {
		printf("pstm_read_unsigned_bin b error\n");
		return 0;
	}
	if (pstm_init_for_read_unsigned_bin(NULL, &m, m_len) < 0) {
		printf("pstm_init_for_read_unsigned_bin c error\n");
		return 0;
	}
	if (pstm_read_unsigned_bin(&m, m_raw, m_len) != 0) {
		printf("pstm_read_unsigned_bin c error\n");
		return 0;
	}

	if (pstm_init(NULL, &r) != 0) {
		printf("pstm_init r error\n");
		return 0;
	}

	if (pstm_exptmod(NULL, &a, &b, &m, &r) != 0) {
		printf("pstm_exptmod error\n");
		return 0;
	}

	if (pstm_to_unsigned_bin(0, &r, rr) < 0) {
		printf("pstm_to_unsigned_bin error\n");
		return 0;
	}
	s = pstm_unsigned_bin_size(&r);
	buf = buf_ptr = malloc(s * 2 + 1);
	for (i = 0; i < s; i++) {
		buf_ptr += sprintf(buf_ptr, "%02X", rr[i]);
	}

	printf("matrixssl:\n%s\n", buf);
	return buf;
}

int main(int argc, char *argv[])
{
	matrixtest(a1, a1_len, b1, b1_len, m1, m1_len);

}
