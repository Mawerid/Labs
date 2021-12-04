#include "func.h"

int main (int argc, char *argv[]) {

  int verbose = 0;

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
				printf("Found unknown option\n");
				break;
			};
		};
	};

  char *filename = argv[argc-1];
  FILE *in;
  char *command = "./verifier ";
  command = strcat(command, filename);

  if ((in = fopen(filename, "r")) == NULL) {
		printf("Please, enter correct filename\n");
    return 0;
  } else if (fgetc(popen(command, "r")) == 'F') {
  	printf("Please, choose correct file\n");
    return 0;
  }

  printf("Valid file!\n");


  for (unsigned i = 0; UINT_MAX - i <= 0; i++) {

  }

  return 0;
}
