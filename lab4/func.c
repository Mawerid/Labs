#include "func.h"

int checker(FILE *in) {
  char letter;
  int i;
  int flag = 0;
  int max_len[NUM_TYPES_CIPHERS] = {
    MAXLEN_3DES,
    MAXLEN_AES128,
    MAXLEN_AES192,
    MAXLEN_AES256};
  int min_len[NUM_TYPES_CIPHERS] = {
    MINLEN_3DES,
    MINLEN_AES128,
    MINLEN_AES192,
    MINLEN_AES256};
  int cipher_type;

  letter = fgetc(in);

  for(i = 0; letter != EOF; i++) {

    switch (i) {
      case 0:
        if (letter != 'E') {
          flag = 1;
        }
        break;
      case 1:
        if (letter != 'N') {
          flag = 1;
        }
        break;
      case 2:
        if (letter != 'C') {
          flag = 1;
        }
        break;
      case 3:
        if (!((letter == 0) || (letter == 1))) {
          flag = 1;
        }
        break;
      case 4:
        if (!((letter >= 0) && (letter <= 3))) {
          flag = 1;
        } else {
          cipher_type = letter;
        }
        break;
    }

    if (flag) {
      break;
    }
    letter = fgetc(in);
  }

  if ((i > max_len[cipher_type]) || (i < min_len[cipher_type])) {
    return 0;
  } else {
    return 1;
  }

}

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

void des3_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
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

void aes_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out, unsigned iv_len) {
  AES_KEY akey;
	AES_set_encrypt_key(key, iv_len, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void hmac_md5(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md) {
  MD5_CTX context;
  unsigned char ipad[PADS_LEN];
  unsigned char opad[PADS_LEN];

  memset(ipad, 0x36, PADS_LEN);
  memset(opad, 0x5c, PADS_LEN);

  for (int i = 0; i < key_len; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  MD5_Init(&context);
  MD5_Update(&context, ipad, (PADS_LEN-1));
  MD5_Update(&context, text, text_len);
  MD5_Final(md, &context);

  MD5_Init(&context);
  MD5_Update(&context, opad, (PADS_LEN-1));
  MD5_Update(&context, text, HMAC_MD5_LEN);
  MD5_Final(md, &context);
}

void hmac_sha1(unsigned char *text, size_t text_len, unsigned char *key, size_t key_len, unsigned char *md) {
  SHA_CTX context;
  unsigned char ipad[PADS_LEN];
  unsigned char opad[PADS_LEN];

  memset(ipad, 0x36, PADS_LEN);
  memset(opad, 0x5c, PADS_LEN);

  for (int i = 0; i < key_len; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }

  SHA1_Init(&context);
  SHA1_Update(&context, ipad, (PADS_LEN-1));
  SHA1_Update(&context, text, text_len);
  SHA1_Final(md, &context);

  SHA1_Init(&context);
  SHA1_Update(&context, opad, (PADS_LEN-1));
  SHA1_Update(&context, text, HMAC_SHA1_LEN);
  SHA1_Final(md, &context);
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

void readinfo(FILE *in, int *hash_type, int *ci_type, char *nonce, char *iv, char *ciphertext, int *ct_len) {

  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256};

  char letter;
  int i = 0;

  letter = fgetc(in);
  i++;
  letter = fgetc(in);
  i++;
  letter = fgetc(in);
  i++;

  letter = fgetc(in);
  i++;
  *hash_type = letter;

  letter = fgetc(in);
  i++;
  *ci_type = letter;

  letter = fgetc(in);

  for(; letter != EOF; i++) {
    if (i < NONCE_LEN + 4)
      nonce[i - 5] = letter;

    if ((i > NONCE_LEN + 3) && (i < NONCE_LEN + 4 + IV_LEN[*ci_type]))
      iv[i - NONCE_LEN - 5] = letter;

    if (i > NONCE_LEN + 4 + IV_LEN[*ci_type]) {
      ciphertext[i - NONCE_LEN - 4 - IV_LEN[*ci_type]] = letter;
      (*ct_len)++;
    }

    letter = fgetc(in);
  }

  ciphertext[i] = '\0';
}

void print_data(int hash_type, int ci_type, char *nonce, char *iv, char *ciphertext, int ct_len) {

  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256};

  printf("HMAC_");
  if (hash_type == 0)
    printf("MD5, ");
  else
    printf("SHA1, ");

  switch (ci_type) {
    case 0:
      printf("3DES\n");
      break;
    case 1:
      printf("AES128\n");
      break;
    case 2:
      printf("AES192\n");
      break;
    case 3:
      printf("AES256\n");
      break;
  }

  printf("NONCE: ");
  for (int i = 0; i < NONCE_LEN; i++)
    printf("%02hhx", nonce[i]);

  printf("\n");

  printf("IV: ");
  for (int i = 0; i < IV_LEN[ci_type]; i++)
      printf("%02hhx", iv[i]);

  printf("\n");

  printf("CT: ");
  for (int i = 0; i < ct_len; i++)
        printf("%02hhx", ciphertext[i]);

  printf("\n");
}
