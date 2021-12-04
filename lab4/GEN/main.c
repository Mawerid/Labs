#include "../func.h"

int main (int argc, char *argv[]) {
  if (argc == 4) {

    unsigned password = str_hex(argv[1]);
    char * hash_type = argv[2];
    char * cipher_type = argv[3];
    char * text = TEXT;
    char * opentext;
    char * ciphertext;
    char filename[30];

    if (!((strcmp(hash_type, "md5") == 0) || (strcmp(hash_type, "sha1") == 0))) {
      printf("Sorry, incorrect hash type.\n");
      return 0;
    } else if (!((strcmp(cipher_type, "3des") == 0) || (strcmp(cipher_type, "aes128") == 0) ||
                (strcmp(cipher_type, "aes192") == 0) || (strcmp(cipher_type, "aes256") == 0))) {
      printf("Sorry, incorrect cipher type.\n");
      return 0;
    }

    int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256}; // depend of cipher type
    //int MAX_LEN[NUM_TYPES_CIPHERS] = {MAXLEN_3DES, MAXLEN_AES128, MAXLEN_AES192, MAXLEN_AES256};
    int ci_type = 0;

    if (strcmp(cipher_type, "3des") == 0) {
      ci_type = DES3;
    } else if (strcmp(cipher_type, "aes128") == 0) {
      ci_type = AES128;
    } else if (strcmp(cipher_type, "aes192") == 0) {
      ci_type = AES192;
    } else {
      ci_type = AES256;
    }

    opentext = (char *) malloc((strlen(text) + 8) * sizeof(char));
    for (int i = 0; i < 8; i++) {
      opentext[i] = 0;
    }
    for (int i = 0; i < strlen(text); i++) {
      opentext[i + 8] = text[i];
    }

    ciphertext = (char*) malloc(MAX_TEXT_LEN * sizeof(char));

    char nonce[NONCE_LEN];
    char iv[IV_LEN[ci_type]];
    char key[IV_LEN[ci_type]];

    generate(nonce, NONCE_LEN);
    generate(iv, IV_LEN[ci_type]);

    hmac(password, nonce, key, hash_type, IV_LEN[ci_type]);

    for (int i = 0; i < IV_LEN[ci_type]; i++) {
      key[i] = 0xff;
    }

    if (ci_type == 0) {
      des3_cbc_encrypt((unsigned char *) opentext, (strlen(text) + 8), (unsigned char *)iv, (unsigned char *)key, (unsigned char *)ciphertext);
    } else {
      aes_cbc_encrypt((unsigned char *) opentext, (strlen(text) + 8), (unsigned char *)iv, (unsigned char *)key, (unsigned char *)ciphertext, IV_LEN[ci_type] * BYTE_LEN);
    }

    create_filename(hash_type, cipher_type, password, filename);

    file_filling(filename, hash_type, ci_type, nonce, iv, ciphertext, IV_LEN[ci_type], (strlen(text) + 8));

    free(ciphertext);
    free(opentext);

  } else if (argc < 4) {
    printf("Sorry, not enough parameters.\n");
  } else {
    printf("Sorry, too many parameters.\n");
  }

  return 0;
}
