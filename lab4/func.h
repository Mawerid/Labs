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

#define TEXT "I would not like to be one of those worthless handicraftsmen who are only engaged in repairing old products, because they are aware of their inability to create something new."

#define NUM_TYPES_CIPHERS 4

#define IV_LEN_3DES 21
#define IV_LEN_AES128 16
#define IV_LEN_AES192 24
#define IV_LEN_AES256 32

#define KEY_LEN_3DES 21
#define KEY_LEN_AES128 16
#define KEY_LEN_AES192 24
#define KEY_LEN_AES256 32

#define MAXLEN_3DES 4173
#define MAXLEN_AES128 4181
#define MAXLEN_AES192 4189
#define MAXLEN_AES256 4197

#define MINLEN_3DES 78
#define MINLEN_AES128 86
#define MINLEN_AES192 94
#define MINLEN_AES256 102

#define DES3 0
#define AES128 1
#define AES192 2
#define AES256 3

#define PWRD_LEN 4
#define BYTE_LEN 8
#define LEN_CHAR 256
#define MAX_TEXT_LEN 4096
#define NONCE_LEN 64
#define PADS_LEN 65

#define HMAC_MD5_LEN 16
#define HMAC_SHA1_LEN 20

void checker(FILE *in);

unsigned str_hex(const char *str);

void generate(char *string, int len);

void md5(unsigned char *data, size_t data_len, unsigned char *hash);

void sha1(unsigned char *data, size_t data_len, unsigned char *hash);

void des3_cbc_encrypt(unsigned char *in, size_t in_len,
                      unsigned char *iv, unsigned char *key,
                      unsigned char *out);

void aes_cbc_encrypt(unsigned char *in, size_t in_len,
                    unsigned char *iv, unsigned char *key,
                    unsigned char *out, unsigned iv_len);

void hmac_md5(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md);

void hmac_sha1(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md);

void create_filename(char *hash_type, char *cipher_type, unsigned password, char *filename);

void file_filling(char *filename, char *hash_type, int ci_type, char *nonce, char *iv, char *text, int iv_len, int text_len);