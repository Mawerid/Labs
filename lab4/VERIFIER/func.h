#include <stdio.h>
#include <string.h>

#define NUMBER_CIPHER 4
#define MAXLEN_3DES 4173
#define MAXLEN_AES128 4181
#define MAXLEN_AES192 4189
#define MAXLEN_AES256 4197
#define MINLEN_3DES 78
#define MINLEN_AES128 86
#define MINLEN_AES192 94
#define MINLEN_AES256 102

void checker(FILE *in);
