LIBS = -lhpcap -lnuma -lpcap -lpthread
LIB_DIR = -L../../lib 
#FLAGS = -O2 -g -Wall
FLAGS = -O3 -g -Wall -D_GNU_SOURCE
#FLAGS = -g -Wall

.PHONY: clean

all: lib dupinfo

dupinfo: dupinfo.c
	gcc $(FLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

lib:
	cd ../../lib/;\
	make clean;\
	make

clean:
	rm -f dupinfo *.o *~
