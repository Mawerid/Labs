#include "cryptaes.h"
#include "otherfun.h"

#define KEYCOUNT			3
#define VERSION 		  0.1

int main(int argc, char **argv) {

    unsigned init_vector = 0;
    unsigned key0 = 0;
    
    int enc = 2;
    int typeisecb = 1;
    int debug_mode = 0;
    int need2done = 1;
    int iskey = 0;
    int isiv = 0;
    
    opterr = 0;
    
	const char *short_options = "hvm:edk:i:g";
	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"mode", required_argument, NULL, 'm'},
		{"enc", no_argument, NULL, 'e'},
		{"dec", no_argument, NULL, 'd'},
		{"key", required_argument, NULL, 'k'},
		{"iv", required_argument, NULL, 'i'},
		{"debug", no_argument, NULL, 'g'}, 
		{NULL, 0, NULL, 0}
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
				enc = 1;
				break;
			};
			case 'd': {
				enc = 0;
				break;
			};
			case 'k': {
				key0 = str_hex(optarg);
				iskey = 1;
				break;
			};
			case 'i': {
				init_vector = str_hex(optarg);
				isiv = 1;
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
    
    else if (enc == 2)
    	printf("Please, enter mode (encoding or decoding)\nUse --help (or -h) to get documentation\n");
    
    else if (!(iskey) || (typeisecb == 0 && isiv == 0))
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

	    generate_keys(key[0], &key[1], &key[2]);
	    
	    if (debug_mode) {
	    	printf("\n-----------------------\n");
	    	if (typeisecb)
	    		printf("This is AES in Electronic Codebook mode of ");
	    	else 
	    		printf("This is AES in Cipher block chaining mode of ");
	    	
	    	if (enc)
	    		printf("encoding\n");
	    	else
	    		printf("decoding\n");
	    	printf("-----------------------\n");
	    	for (int j = 0; j < KEYCOUNT; j++)
	    		printf("Key %d value: %x\n", j, key[j]);
	    }

	    while ((c = fgetc(in)) != EOF) {
	        hex_block[i] = c;
	        i++;
	        if (i == 8) {
	            inf_block = str_hex(hex_block);
	            
	            if (debug_mode) {
	            	printf("\n-----------------------\n");
	            	printf("Just read this block of information:      %s\n", hex_block);
	            }
	            
	            if (typeisecb) {
	                cipher = ecb(key, inf_block, enc, debug_mode);
	                
	                if (debug_mode) {
	                	printf("This block of information after ");
	                	if (enc)
	    					printf("encoding: ");
	    				else
	    					printf("decoding: ");
	    			}
	    			
	                printf("%08x", cipher);
	            } else {
	                cipher = cbc(key, inf_block, init_vector, enc, debug_mode);
	                
	                if (debug_mode) {
	                	printf("Use init vector: %u\n", init_vector);
	                	printf("This block of information after ");
	                	if (enc)
	    					printf("encoding: ");
	    				else
	    					printf("decoding: ");
	    			}
	    			
	    			if (!enc)
	    				init_vector = inf_block;
	    			else
	                	init_vector = cipher;
	                printf("%08x", cipher);
	            }
	            i = 0;
	            for (int j = 0; j < 8; j++)
	                hex_block[j] = '0';
	        }
	    }
	    if (i > 2) {
	        inf_block = str_hex(hex_block);
	        
	        if (debug_mode) {
	           	printf("\n-----------------------\n");
	           	printf("\nJust read this block of information:      %s\n", hex_block);
	        }
	            
	        if (typeisecb) {
	            cipher = ecb(key, inf_block, enc, debug_mode);
	            
	            if (debug_mode) {
	               printf("This block of information after ");
	               if (enc)
	  					printf("encoding: ");
	    		   else
	    		   		printf("decoding: ");
	    		}
	    		
	            printf("%08x", cipher);
	        } else {
	            cipher = cbc(key, inf_block, init_vector, enc, debug_mode);
	            
	            if (debug_mode) {
	               printf("Use init vector: %u\n", init_vector);
	               printf("This block of information after ");
	               if (enc)
	   					printf("encoding: ");
	    		   else
	    			   	printf("decoding: ");
	    		}
	    		
	            printf("%08x", cipher);
	        }
    	}
    	
	    printf("\n");
	    if (debug_mode) {
	    	printf("\n-----------------------\n");
	        printf("This is the end of ");
	        if (enc)
	   			printf("encoding.\n");
	    	else
	 			printf("decoding.\n");
	    }
	    fclose(in);
    }
    return 0;
}

