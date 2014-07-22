LIBS = -lhpcap -lnuma -lpcap -lpthread
LIB_DIR = -L../../lib 
#FLAGS = -O2 -g -Wall
FLAGS = -g -Wall

.PHONY: clean

all: raw2tstamp raw2pcap

raw2pcap: raw2pcap.c
	gcc $(FLAGS) -o $@ $^ $(LIB_DIR) $(LIBS)
raw2tstamp: raw2tstamp.c
	gcc $(FLAGS) -o $@ $^ $(LIB_DIR) $(LIBS)

clean:
	rm -f raw2pcap raw2tstamp *.o *~
