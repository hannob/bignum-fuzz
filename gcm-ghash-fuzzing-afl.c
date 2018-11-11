/*

for matrixssl vs openssl:
afl-clang-fast gcm2.c -I /mnt/ram/matrixssl-3-8-3-open/ -lssl -lcrypto
afl-clang-fast/libcrypt_s.a afl-clang-fast/libcore_s.a

for openssl vs. nss:
gcc -g gcm.c  -lcrypto -fsanitize=address -I/usr/include/nspr -I/usr/include/nss
/usr/lib/libfreebl.a /usr/lib/libnspr4.so /usr/lib/libnssutil3.so  -Wall
-pedantic

afl-gcc -O2 gcm.c -o gcm libcrypto.a libfreebl.a libnspr4.a -I/usr/include/nspr
-I/usr/include/nss -lpthread -ldl /usr/lib/libnssutil3.so
*/

//#define NO_OPENSSL 1
//#define NO_GCRYPT 1
#define NO_NSS 1
#define NO_MBED 1
#define NO_MATRIX 1
#define NO_CYCLONE 1

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#ifndef NO_NSS
#include <pkcs11t.h>
#include <private/blapi.h>
#endif

#ifndef NO_MBED
#include <mbedtls/gcm.h>
#endif

/* matrixssl */
#ifndef NO_MATRIX
#include <crypto/cryptoApi.h>
#endif

#ifndef NO_CYCLONE
#include <aes.h>
#include <cipher_mode_gcm.h>
#endif

#ifndef NO_GCRYPT
#include <gcrypt.h>
#endif

#define KEYLEN 16 /* 16 = 128 bit */
#define IVLEN 12  /* 12 = 96 bit, default */
#define TAGLEN 16

int main(int argc, char **argv) {
  FILE *f;
  unsigned char buf[4096];
  unsigned char enc[8192];
  unsigned char tag[16];
  unsigned char *key;
  unsigned char *iv;
  unsigned char *input;
  unsigned char mout[4096];
  unsigned char mtag[16];
  unsigned char gcrypttag[16];
  size_t s;
  int i, j;
  unsigned int u;
  EVP_CIPHER_CTX *ctx;
#ifndef NO_NSS
  AESContext *ac;
  CK_GCM_PARAMS gcmparams;
  unsigned char *params;
#endif
  unsigned char *empty = (unsigned char *)"";
#ifndef NO_MBED
  mbedtls_gcm_context mgcm;
#endif
#ifndef NO_MATRIX
  psAesGcm_t mactx;
  unsigned char *somebuf;
  unsigned char matrixtag[16];
#endif
#ifndef NO_CYCLONE
  AesContext aesc;
  unsigned char cyclonetag[16];
#endif
#ifndef NO_GCRYPT
  gcry_cipher_hd_t gcipher;
#endif

  if (argc < 2) {
    printf("No file given\n");
    return 1;
  }
  f = fopen(argv[1], "rb");
  s = fread(buf, 1, 4096, f);

  if (s < KEYLEN + IVLEN + 1)
    return -1;
  s -= KEYLEN + IVLEN;
  key = buf;
  iv = buf + KEYLEN;
  input = buf + KEYLEN + IVLEN;

#ifndef NO_CYCLONE
  /* CycloneCrypto */
  aesInit(&aesc, key, KEYLEN);
  gcmEncrypt(&aesCipherAlgo, &aesc, iv, IVLEN, input, s, empty, buf, 0,
             cyclonetag, TAGLEN);
  for (i = 0; i < 16; i++)
    printf("%02x:", cyclonetag[i]);
  printf("\n");
#endif

#ifndef NO_MATRIX
  /* matrixssl */
  psAesInitGCM(&mactx, key, KEYLEN);
  psAesReadyGCM(&mactx, iv, input, s);
  psAesEncryptGCM(&mactx, empty, somebuf, 0);
  psAesGetGCMTag(&mactx, 16, matrixtag);
  for (i = 0; i < 16; i++)
    printf("%02x:", matrixtag[i]);
  printf("\n");
#endif

#ifndef NO_MBED
  /* mbedtls */
  mbedtls_gcm_init(&mgcm);
  mbedtls_gcm_setkey(&mgcm, MBEDTLS_CIPHER_ID_AES, key, 128);
  mbedtls_gcm_crypt_and_tag(&mgcm, MBEDTLS_GCM_ENCRYPT, 0, iv, IVLEN, input, s,
                            empty, mout, 16, mtag);
  mbedtls_gcm_free(&mgcm);
  for (i = 0; i < 16; i++)
    printf("%02x:", mtag[i]);
  printf("\n");
#endif

#ifndef NO_GCRYPT
  gcry_cipher_open(&gcipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
  gcry_cipher_setkey(gcipher, buf, KEYLEN);
  gcry_cipher_setiv(gcipher, buf + KEYLEN, IVLEN);
  gcry_cipher_authenticate(gcipher, buf + KEYLEN + IVLEN, s);
  gcry_cipher_gettag(gcipher, gcrypttag, 16);
  for (j = 0; j < 16; j++)
    printf("%02x:", gcrypttag[j]);
  printf("\n");
#endif

#ifndef NO_OPENSSL
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), 0, 0, 0);
  /* EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, 0); */ /* only
                                                                       needed if
                                                                       != 12 */
  EVP_EncryptInit_ex(ctx, 0, 0, buf, buf + KEYLEN);
  EVP_EncryptUpdate(ctx, 0, &i, buf + KEYLEN + IVLEN, s);
  EVP_EncryptFinal_ex(ctx, empty, &i);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
  EVP_CIPHER_CTX_free(ctx);
  for (i = 0; i < 16; i++)
    printf("%02x:", tag[i]);
  printf("\n");
#endif

#ifndef NO_NSS
  gcmparams.pIv = buf + KEYLEN;
  gcmparams.ulIvLen = IVLEN;
  gcmparams.pAAD = buf + KEYLEN + IVLEN;
  gcmparams.ulAADLen = s;
  gcmparams.ulTagBits = 16 * 8;
  params = (unsigned char *)&gcmparams;
  ac = AES_CreateContext(buf, params, NSS_AES_GCM, 1, KEYLEN, 16);
  AES_Encrypt(ac, enc, &u, 8192, empty, 0);
  for (j = 0; j < u; j++)
    printf("%02x:", enc[j]);
  printf("\n");
#endif

  assert(memcmp(gcrypttag, tag, 16) == 0);

  return 0;
}
