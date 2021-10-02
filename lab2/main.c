#include "cryptaes.h"

#define KEYCOUNT 3

int main() {
    FILE *in;
    in = fopen("input.txt", "r");
    unsigned key[KEYCOUNT] = {0xabcdef71, 0, 0};
    generate_keys(key[0],&key[1],&key[2]);
    unsigned cipher;
    cipher = cbc(key, 0x01234567, 0xb6a4ea1b, 1);
    printf("%x", cipher);
    cipher = cbc(key, 0x89abcdef, cipher, 1);
    printf("%x", cipher);
    return 0;
}
