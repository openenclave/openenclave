include ../../mak/defs.mak

TARGET=$(LIBDIR)/tmp/libunwind.a

all: .configure
	$(MAKE) -C libunwind/src
	cp ./libunwind/src/.libs/libunwind.a $(TARGET)


OPTS += --enable-shared=no
OPTS += --disable-block-signals 
OPTS += --enable-debug=no
OPTS += --enable-debug-frame==no
OPTS += --enable-cxx-exceptions

CFLAGS += -DUNW_LOCAL_ONLY
CFLAGS += -DWSIZE=8
CFLAGS += -fno-builtin
CFLAGS += -fPIC 
CFLAGS += -DOPEN_ENCLAVE
CFLAGS += -include $(TOP)/3rdparty/libunwind/stubs.h

#CFLAGS += -std=c99

configure:
	( cd libunwind; ./autogen.sh )
	( cd libunwind; ./configure $(OPTS) CFLAGS="$(CFLAGS)" )
	touch .configure

.configure:
	$(MAKE) configure

clean:
	@ $(MAKE) -s clean-silent

clean-silent:
	-@ $(MAKE) -C libunwind clean 2> /dev/null > /dev/null

clone:
	git clone https://github.com/pathscale/libunwind

DISTCLEAN += libunwind/Makefile
DISTCLEAN += libunwind/autom4te.cache/output.0
DISTCLEAN += libunwind/autom4te.cache/output.1
DISTCLEAN += libunwind/INSTALL
DISTCLEAN += libunwind/Makefile.bak
DISTCLEAN += libunwind/Makefile.in
DISTCLEAN += libunwind/aclocal.m4
DISTCLEAN += libunwind/autom4te.cache
DISTCLEAN += libunwind/config.log
DISTCLEAN += libunwind/config.status
DISTCLEAN += libunwind/config/
DISTCLEAN += libunwind/configure
DISTCLEAN += libunwind/doc/Makefile.in
DISTCLEAN += libunwind/include/config.h
DISTCLEAN += libunwind/include/config.h.in
DISTCLEAN += libunwind/include/config.h.in~
DISTCLEAN += libunwind/include/libunwind-common.h
DISTCLEAN += libunwind/include/stamp-h1
DISTCLEAN += libunwind/libtool
DISTCLEAN += libunwind/src/Makefile.in
DISTCLEAN += libunwind/tests/Makefile.in

distclean: clean
	@ $(MAKE) -s distclean-silent
	rm -rf $(DISTCLEAN)
	rm -f .configure

distclean-silent:
	-@ ( cd libunwind; $(MAKE) distclean ) 2> /dev/null > /dev/null

diff:
	( cd libunwind; git diff > ../libunwind.diff )

