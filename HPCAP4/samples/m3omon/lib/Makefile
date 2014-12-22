CFLAGS =  -lpcap -lm -lpthread  -Wall -D_GNU_SOURCE -I../../../include -L../../../lib

CC = gcc

all: libmgmon

libmgmon: libmgmon.c
	gcc -O2 -c -g -Wall $(CFLAGS) -o libmgmon.o libmgmon.c
	ar rcs libmgmon.a libmgmon.o

clean: 
	rm -fr *.o *.a
