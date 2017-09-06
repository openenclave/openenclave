include ../../mak/defs.mak

all: musl

VERSION=1.1.10
BASE=musl-$(VERSION)
PKG=$(BASE).tar.gz

CONFIGURE_OPTS += --prefix=$(CURDIR)/install
CONFIGURE_OPTS += --includedir=$(INCDIR)/enclave/libc

CFLAGS = -fPIC

TARGET = $(INCDIR)/enclave/libc

all: musl $(TARGET)

$(TARGET):
	$(MAKE) configure
	$(MAKE) -C musl
	$(MAKE) -C musl install
	./wrap $(TARGET)/endian.h endian.h.prefix endian.h.suffix

configure:
	( cd musl; ./configure $(CONFIGURE_OPTS) CFLAGS=$(CFLAGS) )

musl:
	rm -rf musl
	wget http://www.musl-libc.org/releases/$(PKG)
	tar zxvf $(PKG)
	mv $(BASE) musl
	rm -rf $(PKG)

clean:
	$(MAKE) -C musl clean
	rm -rf $(TARGET)

distclean:
	rm -rf musl $(TARGET)

depend:
