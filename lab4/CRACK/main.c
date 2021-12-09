#include "../func.h"

int main (int argc, char *argv[]) {

  int verbose = 0;
  int problem = 0;

  opterr = 0;

	const char *short_options = "v";
	const struct option long_options[] = {
		{"verbose", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};

	int rez;
	int option_index;

	while ((rez=getopt_long(argc,argv,short_options,
		long_options,&option_index))!=-1){

		switch (rez){
			case 'v': {
				verbose = 1;
				break;
			};
			case '?': default: {
        problem = 1;
				printf("Found unknown option\n");
				break;
			};
		};
	};

  if (problem)
    return 0;

  char *filename = argv[argc-1];
  FILE *in;
  int pass = 0;

  if ((in = fopen(filename, "rb")) == NULL) {
		printf("Please, enter correct filename\n");
    return 0;
  }

  pass = checker(in);

  fclose(in);

  if (!(pass)) {
    printf("Invalid file.\n");
    return 0;
  }

  printf("Valid file!\n");

  int hash_type = 0;
  int ci_type = 0;
  int KEY_LEN[NUM_TYPES_CIPHERS] = {KEY_LEN_3DES, KEY_LEN_AES128, KEY_LEN_AES192, KEY_LEN_AES256};
  int IV_LEN[NUM_TYPES_CIPHERS] = {IV_LEN_3DES, IV_LEN_AES128, IV_LEN_AES192, IV_LEN_AES256};


  unsigned char nonce[NONCE_LEN];
  unsigned char iv[MAX_IV_LEN];
  unsigned char ciphertext[MAX_TEXT_LEN];
  int ct_len = 0;
  unsigned int_pwrd;

  in = fopen(filename, "rb");

  readinfo(in, &hash_type, &ci_type, nonce, iv, ciphertext, &ct_len);

  print_data(hash_type, ci_type, nonce, iv, ciphertext, ct_len);

  fclose(in);

  printf("\nStart cracking\n\n\n");

  unsigned char password[PWRD_LEN];
  unsigned char key[KEY_LEN[ci_type]];
  unsigned char opentext[ct_len];
  unsigned char iv_cpy[IV_LEN[ci_type]];
  int isright = 0;
  unsigned i = 0;

  for (int j = 0; j < IV_LEN[ci_type]; j++)
    iv_cpy[j] = iv[j];

  double time_in_seconds = 0;

  clock_t start = clock();
  clock_t current = clock();
  clock_t previous = clock();

  printf("Current: 00000000 - 0000ffff\n");

  for (; i <= UINT_MAX; i++) {

    int_pwrd = i;
    isright = 1;

    for (int j = 0; j < IV_LEN[ci_type]; j++)
      iv[j] = iv_cpy[j];

    for (int j = 0; j < PWRD_LEN; j++) {
      password[PWRD_LEN - 1 - j] = (unsigned char) int_pwrd % LEN_CHAR;
      int_pwrd /= LEN_CHAR;
    }




    if ((!(i & 0xffff)) && (verbose) && (i != 0)) {
      previous = current;
      current = clock();

      printf("Current: %08x - %08x | ", i, (i + 0xffff));

      time_in_seconds = (double) (current - previous) / CLOCKS_PER_SEC;
      printf("Current speed: %6.0f c/s | ", (0x10000 / time_in_seconds));

      time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
      printf("Average speed: %6.0f c/s\n", (i / time_in_seconds));

    }





    if (hash_type == 0) {

      unsigned char hmac[HMAC_MD5_LEN];

      hmac_md5(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

      for(int j = 0; j < HMAC_MD5_LEN; j++)
        key[j] = hmac[j];


      if (HMAC_MD5_LEN < KEY_LEN[ci_type]) {

        int delta = KEY_LEN[ci_type] - HMAC_MD5_LEN;
        unsigned char tmp_hmac[HMAC_MD5_LEN];
        hmac_md5(hmac, HMAC_MD5_LEN, password, PWRD_LEN, tmp_hmac);

        for (int j = 0; j < delta; j++)
          key[KEY_LEN[ci_type] - delta + j] = tmp_hmac[j];

      }
    } else {

      unsigned char hmac[HMAC_SHA1_LEN];

      hmac_sha1(nonce, NONCE_LEN, password, PWRD_LEN, hmac);

      if (HMAC_SHA1_LEN >= KEY_LEN[ci_type]) {

        for(int j = 0; j < KEY_LEN[ci_type]; j++)
          key[j] = hmac[j];

      } else if (HMAC_SHA1_LEN < KEY_LEN[ci_type]) {

        for(int j = 0; j < HMAC_SHA1_LEN; j++)
          key[j] = hmac[j];

        int delta = KEY_LEN[ci_type] - HMAC_SHA1_LEN;
        unsigned char tmp_hmac[HMAC_SHA1_LEN];
        hmac_md5(hmac, HMAC_SHA1_LEN, password, PWRD_LEN, tmp_hmac);

        for (int j = 0; j < delta; j++)
          key[KEY_LEN[ci_type] - delta + j] = tmp_hmac[j];

      }
    }





    if (ci_type == 0) {

      des3_cbc_decrypt(ciphertext, ct_len, iv, key, opentext);

    } else {

      aes_cbc_decrypt(ciphertext, ct_len, iv, key, opentext, KEY_LEN[ci_type] * BYTE_LEN);

    }


    // printf("\nMessage's text is: \n\n");
    // for (int j = NULL_CHECK_LEN; j < ct_len; j++) {
    //   printf("%c", opentext[j]);
    // }
    //
    // printf("\n\n");
    // for (int j = 0; j < ct_len; j++) {
    //   printf("%02hhx", opentext[j]);
    // }
    //
    // printf("\n\n");


    for (int j = 0; j < NULL_CHECK_LEN; j++) {
      if (opentext[j] != 0){
        isright = 0;
        break;
      }
    }

    if (i == UINT_MAX)
      break;

    if (isright)
      break;

  }

  current = clock();

  printf("Found: ");
  for (int j = 0; j < PWRD_LEN; j++) {
    printf("%02hhx", password[j]);
  }

  if (verbose) {
    time_in_seconds = (double) (current - start) / CLOCKS_PER_SEC;
    printf(" | Average speed: %6.0f c/s\n", (i / time_in_seconds));
  }


  printf("\nMessage's text is: \n\n");
  for (int j = NULL_CHECK_LEN; j < ct_len; j++) {
    printf("%c", opentext[j]);
  }

  printf("\n\n");

  printf("\nMessage's text in HEX is: \n\n");
  for (int j = NULL_CHECK_LEN; j < ct_len; j++) {
    printf("%02hhx", opentext[j]);
  }

  printf("\n\n");

  return 0;
}
