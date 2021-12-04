all: crack gen verifier

crack:
	gcc CRACK/main.c CRACK/func.c -Wall -lssl -lcrypto -o crack

gen:
	gcc GEN/main.c GEN/func.c -Wall -lssl -lcrypto -o gen

verifier:
	gcc VERIFIER/main.c VERIFIER/func.c -Wall -o verifier

clean:
	rm if *.o
