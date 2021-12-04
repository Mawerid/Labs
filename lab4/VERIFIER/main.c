#include "func.h"

int main (int argc, char *argv[]) {
    FILE *in;
    int len = strlen(argv[1]);
    if ((argv[1][len-3] == '.') && (argv[1][len-2] == 'e') && (argv[1][len-1] == 'n') && (argv[1][len] == 'c')) {
      printf("Please, enter a correct filename to check\n");
      return 0;
    } else if ((in = fopen(argv[1], "r")) == NULL) {
      printf("Please, enter a correct filename to check\n");
      return 0;
    } else {
      checker(in);
      fclose(in);
      return 0;
    }
}
