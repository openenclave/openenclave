#!/usr/bin/make -f

all: update-dlmalloc
	echo All done - please review changes

update-dlmalloc:
	rm -rf dlmalloc
	mkdir -p dlmalloc
	( cd dlmalloc; wget ftp://gee.cs.oswego.edu/pub/misc/malloc.h )
	( cd dlmalloc; wget ftp://gee.cs.oswego.edu/pub/misc/malloc.c )
