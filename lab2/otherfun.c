#include "otherfun.h"

unsigned str_hex(const char * str){
    const char * ptr;
    unsigned num;
    num = 0;
    for (ptr = str; *ptr; ptr++) {
        if (*ptr >= '0' && *ptr <= '9')
            num = (num << 4) | (unsigned int)(*ptr - '0');
        else if (*ptr >= 'A' && *ptr <= 'F')
            num = (num << 4) | (unsigned int)(*ptr - 'A' + 10);
        else if (*ptr >= 'a' && *ptr <= 'f')
            num = (num << 4) | (unsigned int)(*ptr - 'a' + 10);
    }
    return num;
}
