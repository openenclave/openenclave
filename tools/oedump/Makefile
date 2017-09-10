include ../../mak/defs.mak

PROGRAM = $(BINDIR)/oedump

INCLUDES += -I$(INCDIR)

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread

all:
	$(MAKE) program

CLEAN += log.txt pages.bin out err echoenc.signed.so private.pem

include $(TOP)/mak/program.mak

tests:
	@ $(BINDIR)/oedump $(TOP)/tests/echo/enc/echoenc.signed.so

nm:
	@ nm -D $(TOP)/tests/echo/enc/echoenc.signed.so

distclean:
