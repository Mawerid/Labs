#include "func.h"

void md5(unsigned char *data, size_t data_len, unsigned char *hash) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, data_len);
  MD5_Final(hash, &ctx);
}

void sha1(unsigned char *data, size_t data_len, unsigned char *hash) {
  SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, data_len);
  SHA1_Final(hash, &ctx);
}

void des3_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
  DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;

	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);

	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_DECRYPT);
}

void aes_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out, unsigned iv_len) {
  AES_KEY akey;
	AES_set_encrypt_key(key, iv_len, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void hmac(unsigned password, char *data, char *key, char *hash_type, unsigned key_len) {

  char *ipad;
  char *opad;
  char * tmp_hmac;
  char * tmp_key;
  unsigned tmp_password = password;

  ipad = (char * )malloc(key_len * sizeof(char));
  opad = (char * )malloc(key_len * sizeof(char));
  tmp_hmac = (char * )malloc(key_len * sizeof(char));
  tmp_key = (char * )malloc((key_len) * sizeof(char));

  for (unsigned i = 0; i < key_len; i++) {
    ipad[i] = 0x36;
    opad[i] = 0x5c;
  }

  for (unsigned i = 0; i < key_len; i++) {
    ipad[i] ^= tmp_password % LEN_CHAR;
    opad[i] ^= tmp_password % LEN_CHAR;
    tmp_password /= LEN_CHAR;
  }

  tmp_hmac = strcat(tmp_hmac, ipad);
  tmp_hmac = strcat(tmp_hmac, data);
  if (strcmp(hash_type, "md5") == 0) {

    md5((unsigned char *) tmp_hmac, strlen(tmp_hmac),(unsigned char *) key);
    tmp_key = strcpy(tmp_key, key);
    tmp_key = strcat(tmp_key, opad);
    tmp_hmac = strcpy(tmp_hmac, tmp_key);
    md5((unsigned char *) tmp_hmac, strlen(tmp_hmac),(unsigned char *) key);

  } else {

    sha1((unsigned char *) tmp_hmac, strlen(tmp_hmac),(unsigned char *) key);
    tmp_key = strcpy(tmp_key, key);
    tmp_key = strcat(tmp_key, opad);
    tmp_hmac = strcpy(tmp_hmac, tmp_key);
    sha1((unsigned char *) tmp_hmac, strlen(tmp_hmac),(unsigned char *) key);

  }
  key[key_len - 1] = '\0';
  data = strcpy(data, key);
  tmp_key = strcpy(tmp_key, key);

  if (strlen(key) < key_len) {

  }

  free(ipad);
  free(opad);
  free(tmp_hmac);
  free(tmp_key);
}
