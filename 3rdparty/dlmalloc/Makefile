include ../../mak/defs.mak

CACHEFILE = $(CACHEDIR)/dlmalloc.tar.gz

all: dlmalloc

dlmalloc:
	$(MAKE) $(CACHEFILE)
	tar zxf $(CACHEFILE)

$(CACHEFILE):
	rm -rf dlmalloc
	mkdir -p dlmalloc
	( cd dlmalloc; wget ftp://gee.cs.oswego.edu/pub/misc/malloc.h )
	( cd dlmalloc; wget ftp://gee.cs.oswego.edu/pub/misc/malloc.c )
	tar zcf $(CACHEFILE) dlmalloc

clean:

distclean:
	rm -rf dlmalloc

depend:
