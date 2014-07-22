LIBS = -lhpcap -lnuma -lpcap -lpthread
LIB_DIR = -L../../lib 
#FLAGS = -O2 -g -Wall
FLAGS = -O3 -g -Wall -D_GNU_SOURCE
#FLAGS = -g -Wall

.PHONY: clean

all: lib hpcapdd hpcapdd_p5g

hpcapdd: hpcapdd.c
	gcc $(FLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

hpcapdd_p5g: hpcapdd_p.c
	gcc $(FLAGS) $(LIB_DIR) -o $@ $^ $(LIBS)

lib:
	cd ../../lib/;\
	make clean;\
	make

clean:
	rm -f hpcapdd hpcapdd_p5g *.o *~
