.PHONY: clean

all: libhpcap.a

libhpcap.a: libhpcap.c
	gcc -O2 -c -g -Wall -lpcap -o hpcaplib.o libhpcap.c
	ar rcs libhpcap.a hpcaplib.o

clean:
	rm -f *.o *.a *~
