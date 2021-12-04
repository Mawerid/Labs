#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
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
#define NONCE_LEN 64
#define MAXLEN_3DES 4173
#define MAXLEN_AES128 4181
#define MAXLEN_AES192 4189
#define MAXLEN_AES256 4197
#define DES3 0
#define AES128 1
#define AES192 2
#define AES256 3
#define PWRD_LEN 4
#define BYTE_LEN 8
#define LEN_CHAR 256
#define MAX_TEXT_LEN 4096


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

void hmac(unsigned password, char *data, char *key, char *hash_type, unsigned key_len);

void create_filename(char *hash_type, char *cipher_type, unsigned password, char *filename);

void file_filling(char *filename, char *hash_type, int ci_type, char *nonce, char *iv, char *text, int iv_len, int text_len);
