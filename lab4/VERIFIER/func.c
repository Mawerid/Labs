#include "func.h"

void checker(FILE *in) {
  char letter;
  int i;
  int flag = 0;
  int max_len[NUMBER_CIPHER] = {
    MAXLEN_3DES,
    MAXLEN_AES128,
    MAXLEN_AES192,
    MAXLEN_AES256};
  int min_len[NUMBER_CIPHER] = {
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
    printf("False\n");
  } else {
    printf("True\n");
  }

}
