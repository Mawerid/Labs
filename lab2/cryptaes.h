#include <stdio.h>
#include <unistd.h>

void generate_keys(unsigned k0, unsigned *k1, unsigned *k2);

unsigned ecb(unsigned key[], unsigned inf_block, int enc);

unsigned cbc(unsigned key[], unsigned inf_block, unsigned init_vector, int enc);


