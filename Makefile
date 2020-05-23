CC=gcc
INSTALL=install
prefix=/usr/local
CFLAGS=-Wall -O3
LDFLAGS=

.PHONY : all clean 

all: sha3sum

sha3.o: sha3.c
	$(CC) -c $(CFLAGS) -o $@ $<

sha3sum.o : sha3sum.c
	$(CC) -c $(CFLAGS) -o $@ $<

sha3sum: sha3.o sha3sum.o 
	$(CC) -o $@ $^ ${LDFLAGS}

clean:
	-rm -f *.o sha3sum
