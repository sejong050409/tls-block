all: tls-block

tls-block: tls-block.o
	gcc -o tls-block tls-block.o -lpcap

tls-block.o: tls-block.c headers.h
	gcc -c -o tls-block.o tls-block.c

clean:
	rm -f tls-block
	rm -f *.o
