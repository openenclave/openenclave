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

distclean: clean
	@ $(MAKE) -s distclean-silent
	rm -f libunwind/autom4te.cache/output.0
	rm -f libunwind/autom4te.cache/output.1
	rm -f .configure

distclean-silent:
	-@ ( cd libunwind; $(MAKE) distclean ) 2> /dev/null > /dev/null

diff:
	( cd libunwind; git diff > ../libunwind.diff )

