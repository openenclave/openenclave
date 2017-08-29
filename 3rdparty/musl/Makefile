
all: musl

VERSION=1.1.10
BASE=musl-$(VERSION)
PKG=$(BASE).tar.gz

all: musl

musl:
	rm -rf musl
	wget http://www.musl-libc.org/releases/$(PKG)
	tar zxvf $(PKG)
	mv $(BASE) musl
	rm -rf $(PKG)

clean:

distclean:
	rm -rf musl

depend:
