#include "func.h"

unsigned str_hex(const char *str){
    const char *ptr;
    unsigned num;
    int num_of_simb;
    num_of_simb = 8;
    num = 0;

    for (ptr = str; *ptr; ptr++) {
        if (*ptr >= '0' && *ptr <= '9') {
            num = (num << 4) | (unsigned int)(*ptr - '0');
            num_of_simb--;
        }
        else if (*ptr >= 'A' && *ptr <= 'F') {
            num = (num << 4) | (unsigned int)(*ptr - 'A' + 10);
            num_of_simb--;
        }
        else if (*ptr >= 'a' && *ptr <= 'f') {
            num = (num << 4) | (unsigned int)(*ptr - 'a' + 10);
            num_of_simb--;
        }

    }

    num <<= (num_of_simb*4);

    return num;
}

void generate(char * string, int len) {
  srand(time(NULL));
  for (int i = 0; i < len-1; i++) {
    string[i] = (unsigned char) (rand() % LEN_CHAR);
  }
}

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

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_ENCRYPT);
}

void aes_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out, unsigned iv_len) {
  AES_KEY akey;
	AES_set_encrypt_key(key, iv_len, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}

void hmac(unsigned password, char *data, char *key, char *hash_type, unsigned key_len) {

  char *ipad;
  char *opad;
  char * tmp_hmac;
  char * tmp_key;
  unsigned tmp_password = password;

  ipad = (char * )malloc(64 * sizeof(char));
  opad = (char * )malloc(64* sizeof(char));
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

void create_filename(char *hash_type, char *cipher_type, unsigned password, char *filename) {
  char pwrd[PWRD_LEN * 2 + 1];

  filename = strcpy(filename, hash_type);

  filename[strlen(hash_type)] = '_';
  strcpy((filename + strlen(hash_type) + 1), cipher_type);

  filename[strlen(hash_type) + strlen(cipher_type) + 1] = '_';

  sprintf(pwrd, "%08x", password);
  strcpy((filename + strlen(hash_type) + strlen(cipher_type) + 2), pwrd);

  strcpy((filename + strlen(hash_type) + strlen(cipher_type) + 2 + PWRD_LEN*2), ".enc");
}

void file_filling(char *filename, char *hash_type, int ci_type, char *nonce, char *iv, char *text, int iv_len, int text_len) {
  FILE * output;
  output = fopen(filename, "w");

  if (strcmp(hash_type, "md5") == 0) {
    fprintf(output, "ENC%c", 0);
  } else {
    fprintf(output, "ENC%c", 1);
  }

  fprintf(output, "%c", ci_type);

  for(int i = 0; i < NONCE_LEN; i++) {
    fprintf(output, "%c", nonce[i]);
  }

  for(int i = 0; i < iv_len; i++) {
    fprintf(output, "%c", iv[i]);
  }

  for(int i = 0; i < text_len; i++) {
    fprintf(output, "%c", text[i]);
  }

  fclose(output);
}
