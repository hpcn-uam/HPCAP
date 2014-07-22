CFLAGS =  -O3 -g -Wall -D_GNU_SOURCE
LIBS = -lhpcap -lpcap -lm -lpthread
LIB_DIR =  -L../../../lib -I../../../include

CC = gcc

all: packet_count mrtg flow multicast_tx

packet_count: ../lib/libmgmon.c packet_count.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

mrtg: ../lib/libmgmon.c mrtg.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

flow: ../lib/libmgmon.c flow.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

multicast_tx: ../lib/libmgmon.c multicast_tx.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

multicast_send: multicast_send.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

multicast_receive: multicast_receive.c
	$(CC) $(CFLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

clean: 
	rm -fr *.o packet_count mrtg flow multicast_tx
