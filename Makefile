CFLAGS = -Wall -Werror -Wpedantic -I/usr/include/openssl 
second = -lssl -lcrypto

aswium: main.o 
	gcc $(CFLAGS) main.o $(second)

main.o: ./main.c
	gcc $(CFLAGS) -c ./main.c 