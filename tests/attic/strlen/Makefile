include ../../mak/defs.mak

CFLAGS = -Wall -g -O2

all:
	gcc $(CFLAGS) -o strlen main.c strlen.c

tests:
	/usr/bin/time ./strlen

clean:
	rm strlen
