#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>

#define LEN_CHAR 256
#define BYTE_LEN 8

void md5(unsigned char *data, size_t data_len, unsigned char *hash);

void sha1(unsigned char *data, size_t data_len, unsigned char *hash);

void des3_cbc_decrypt(unsigned char *in, size_t in_len,
                      unsigned char *iv, unsigned char *key,
                      unsigned char *out);

void aes_cbc_decrypt(unsigned char *in, size_t in_len,
                    unsigned char *iv, unsigned char *key,
                    unsigned char *out, unsigned iv_len);

void hmac(unsigned password, char *data, char *key, char *hash_type, unsigned key_len);
