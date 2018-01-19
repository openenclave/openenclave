CFLAGS=-I. -Wall -fno-builtin -ffloat-store -D_GNU_SOURCE
U=mpfr
MPFR=$(U)/lib/libmpfr.a
GMP=$(U)/lib/libgmp.a
#MPFR=-lmpfr
#GMP=-lgmp
T=$(wildcard t*.c)
CC=musl-gcc
#CC=gcc

all: gen check mgen tof toa toe tog tox next prev rnd

%:%.o
%:%.c
	$(CC) -o $@ $(CFLAGS) $^

gen: gen.c util.c mp.c $(MPFR) $(GMP)
	$(CC) -o $@ $(CFLAGS) -lm -I$(U)/include $^

check: gen.c util.c mplibm.c
	$(CC) -o $@ $(CFLAGS) -lm $^

mgen: gen.c util.c mplibm.c
	$(CC) -o $@ $(CFLAGS) -lm $^

clean:
	rm -f gen check mgen tof toa toe tog tox next prev rnd

