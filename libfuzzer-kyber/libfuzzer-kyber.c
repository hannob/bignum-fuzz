/*

  Expected input size: 1152 (additional content in larger files will be ignored)

 */

#include "kyber/ref/params.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void indcpa_enc(unsigned char *c, const unsigned char *m,
		const unsigned char *pk, const unsigned char *coins);

void ref_indcpa_enc(unsigned char *c, const unsigned char *m,
		    const unsigned char *pk, const unsigned char *coins);

int LLVMFuzzerTestOneInput(const uint8_t * datax, size_t size)
{

	unsigned char out1[KYBER_INDCPA_BYTES];
	unsigned char out2[KYBER_INDCPA_BYTES];
	int i;

	unsigned char *data = (unsigned char *)datax;

	if (size <
	    KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_PUBLICKEYBYTES +
	    KYBER_SYMBYTES)
		return 0;

	indcpa_enc(out1, &data[0], &data[KYBER_INDCPA_MSGBYTES],
		   &data[KYBER_INDCPA_MSGBYTES + KYBER_INDCPA_PUBLICKEYBYTES]);
	ref_indcpa_enc(out2, &data[0], &data[KYBER_INDCPA_MSGBYTES],
		       &data[KYBER_INDCPA_MSGBYTES +
			     KYBER_INDCPA_PUBLICKEYBYTES]);

#ifdef DEBUG
	for (i = 0; i < KYBER_INDCPA_BYTES; i++) {
		printf("%02x:", out1[i]);
	}
	printf("\n");
	for (i = 0; i < KYBER_INDCPA_BYTES; i++) {
		printf("%02x:", out2[i]);
	}
	printf("\n");
#endif

	assert(memcmp(out1, out2, KYBER_INDCPA_BYTES) == 0);

	return 0;
}
