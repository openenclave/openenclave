include ../../mak/defs.mak

PROGRAM = $(BINDIR)/oesign

INCLUDES += -I$(INCDIR)

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread -ldl

all:
	$(MAKE) program

CLEAN += log.txt pages.bin out err echoenc.signed.so private.pem

include $(TOP)/mak/program.mak

tests:

distclean:
