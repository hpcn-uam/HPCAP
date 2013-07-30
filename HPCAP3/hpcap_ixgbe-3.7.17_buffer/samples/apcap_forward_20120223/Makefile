LIBS = -lps -lnuma -lpcap -lpthread
LIB_DIR = -L../../lib 
#FLAGS = -O2 -g -Wall
FLAGS = -g -Wall

.PHONY: clean

all: apcap_forward

apcap_forward: apcap_forward.c
	gcc $(FLAGS) -o apcap_forward apcap_forward.c $(LIB_DIR) $(LIBS)

clean:
	rm -f apcap_forward
