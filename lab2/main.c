#include "cryptaes.h"
#include "otherfun.h"

#define KEYCOUNT 3

int main() {
    char * filename = "input.txt";
    unsigned init_vector = 0xb6a4ea1b;
    unsigned key0 = 0xabcdef71;
    int enc = 1;
    int typeisecb = 1;

    FILE *in;
    in = fopen(filename, "r");
    char c;
    char hex_block[] = "00000000";
    int i = 0;
    unsigned inf_block;
    unsigned key[KEYCOUNT] = {key0, 0, 0};
    unsigned cipher;

    generate_keys(key[0],&key[1],&key[2]);

    while ((c = fgetc(in)) != EOF) {
        hex_block[i] = c;
        i++;
        if (i == 8) {
            inf_block = str_hex(hex_block);
            if (typeisecb) {
                cipher = ecb(key, inf_block, enc);
                printf("%x", cipher);
            } else {
                cipher = cbc(key, inf_block, init_vector, enc);
                init_vector = cipher;
                printf("%x", cipher);
            }
            i = 0;
            for (int j = 0; j < 8; j++)
                hex_block[j] = '0';
        }
    }
    if (i > 2) {
        inf_block = str_hex(hex_block);
        if (typeisecb) {
            cipher = ecb(key, inf_block, enc);
            printf("%x", cipher);
        } else {
            cipher = cbc(key, inf_block, init_vector, enc);
            init_vector = cipher;
            printf("%x", cipher);
        }
    }
    printf("\n");
    return 0;
}

