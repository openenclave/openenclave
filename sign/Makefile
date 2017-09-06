include ../mak/defs.mak

PROGRAM = $(BINDIR)/oesign

INCLUDES += -I$(INCDIR) -I$(INCDIR)/host

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread

all:
	$(MAKE) program

CLEAN += log.txt pages.bin out err echoenc.signed.so private.pem

include $(TOP)/mak/program.mak

tests:
