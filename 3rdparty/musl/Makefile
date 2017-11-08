include ../../mak/defs.mak

VERSION=1.1.10
BASE=musl-$(VERSION)
PKG=$(BASE).tar.gz

CONFIGURE_OPTS += --prefix=$(CURDIR)/install
CONFIGURE_OPTS += --includedir=$(INCDIR)/openenclave/libc

CFLAGS = -fPIC

TARGET = $(INCDIR)/openenclave/libc

CACHEFILE = $(CACHEDIR)/musl.tar.gz

CACHEFILE2 = $(CACHEDIR)/libc-test.tar.gz

all: 
	$(MAKE) musl 
	$(MAKE) libc-test
	$(MAKE) $(TARGET)

$(TARGET):
	$(MAKE) configure
	$(MAKE) -C musl install-headers
	( rm -f `find . -name '*.o'` )
	( rm -f `find . -name '*.lo'` )
	./wrap $(TARGET)/endian.h endian.h.prefix endian.h.suffix

configure:
	( cd musl; ./configure $(CONFIGURE_OPTS) CFLAGS=$(CFLAGS) )

musl:
	$(MAKE) $(CACHEFILE)
	tar zxf $(CACHEFILE)

libc-test:
	$(MAKE) $(CACHEFILE2)
	tar zxf $(CACHEFILE2)

$(CACHEFILE):
	rm -rf musl
	wget http://www.musl-libc.org/releases/$(PKG)
	tar zxf $(PKG)
	mv $(BASE) musl
	rm -rf $(PKG)
	tar zcf $(CACHEFILE) musl
	rm -rf musl

$(CACHEFILE2):
	rm -rf libc-test
	git clone git://nsz.repo.hu:45100/repo/libc-test
	tar zcf $(CACHEFILE2) libc-test
	rm -rf libc-test

clean:
	$(MAKE) -s silent-clean

silent-clean:
	-@ $(MAKE) -C musl clean 2> /dev/null
	@ rm -rf $(TARGET) install

distclean:
	rm -rf musl libc-test $(TARGET) install $(PKG)


depend:
