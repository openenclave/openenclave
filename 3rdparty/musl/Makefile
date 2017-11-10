include ../../mak/defs.mak

VERSION=1.1.10
BASE=musl-$(VERSION)
PKG=$(BASE).tar.gz

CONFIGURE_OPTS += --prefix=$(CURDIR)/install
CONFIGURE_OPTS += --includedir=$(INCDIR)/openenclave/libc

CFLAGS = -fPIC

TARGET = $(INCDIR)/openenclave/libc

MUSL_CACHEFILE = $(CACHEDIR)/musl.tar.gz

LIBCTEST_CACHEFILE = $(CACHEDIR)/libc-test.tar.gz

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
	$(MAKE) $(MUSL_CACHEFILE)
	tar zxf $(MUSL_CACHEFILE)

libc-test:
	$(MAKE) $(LIBCTEST_CACHEFILE)
	tar zxf $(LIBCTEST_CACHEFILE)

$(MUSL_CACHEFILE):
	rm -rf musl
	wget http://www.musl-libc.org/releases/$(PKG)
	tar zxf $(PKG)
	mv $(BASE) musl
	rm -rf $(PKG)
	tar zcf $(MUSL_CACHEFILE) musl
	rm -rf musl

$(LIBCTEST_CACHEFILE):
	rm -rf libc-test
	git clone git://nsz.repo.hu:45100/repo/libc-test
	tar zcf $(LIBCTEST_CACHEFILE) libc-test
	rm -rf libc-test

clean:
	$(MAKE) -s silent-clean

silent-clean:
	-@ $(MAKE) -C musl clean 2> /dev/null
	@ rm -rf $(TARGET) install

distclean:
	rm -rf musl libc-test $(TARGET) install $(PKG)

depend:
