include ../../mak/defs.mak

all:
	gcc -Wall -O3 -o hashstr main.c strings.c

tests:
	/usr/bin/time ./hashstr

clean:
	rm hashstr
