CFLAGS =  -g -O3 -Wall -D_GNU_SOURCE
LIBS =  -lpcap -lm -lpthread -lhpcap
LIB_DIR = -L../../../lib -I../../../include 

CC = gcc

all: lib mgmon

mgmon: monitor.c aux.c IPflow.c list.c ../lib/libmgmon.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

lib:
	cd ../../../lib/;\
	make clean;\
	make


clean: 
	rm -fr core *.o mgmon
