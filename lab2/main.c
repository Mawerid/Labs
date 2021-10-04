#include "cryptaes.h"
#include "otherfun.h"

#define KEYCOUNT			3
#define VERSION 		  0.1

int main(int argc, char **argv) {

    unsigned init_vector = 0;
    unsigned key0 = 0;
    int enc = 1;
    int typeisecb = 1;
    int debug_mode = 0;
    opterr = 0;
    int need2done = 1;
    
	const char *short_options = "hvm:edk:i:g";
	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"mode", required_argument, NULL, 'm'},
		{"enc", no_argument, NULL, 'e'},
		{"dec", no_argument, NULL, 'd'},
		{"key", required_argument, NULL, 'k'},
		{"iv", required_argument, NULL, 'i'},
		{"debug", no_argument, NULL, 'g'}
	};	
	
	int rez;
	int option_index;

	while ((rez=getopt_long(argc,argv,short_options,
		long_options,&option_index))!=-1){

		switch (rez){
			case 'h': {
				help();
				need2done = 0;
				break;
			};
			case 'v': {
				double ver = VERSION;
				printf("Version number = %.1lf\n", ver);
				need2done = 0;
				break;
			};
			case 'm': {
				if (!(strcmp(optarg, "cbc")) || !(strcmp(optarg, "CBC")))
					typeisecb = 0;
				break;
			};
			case 'e': {
				break;
			};
			case 'd': {
				enc = 0;
				break;
			};
			case 'k': {
				key0 = str_hex(optarg);
				break;
			};
			case 'i': {
				init_vector = str_hex(optarg);
				break;
			};
			case 'g': {
				debug_mode = 1;
				break;
			};
			case '?': default: {
				printf("Found unknown option\nPlease, use --help (or -h) to get documentation\n");
				break;
			};
		};
	};
	
    char *filename = argv[argc-1];
    FILE *in;
    
    if (!need2done) 
    	return 0;
    
	else if (key0 == 0 || (typeisecb == 0 && init_vector == 0))
		printf("Invalid key or init vector\nPlease, try one more time\n");
	
	else if ((in = fopen(filename, "r")) == NULL)
		printf("Please, enter correct filename\n");
	
	else {
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
    }
    return 0;
}

