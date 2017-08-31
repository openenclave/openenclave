include ../mak/defs.mak

PROGRAM = $(BINDIR)/oesign

INCLUDES += -I$(TOP)/include/host

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/libhost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread

all:
	$(MAKE) program

CLEAN += log.txt pages.bin out err echoenc.signed.so private.pem

include $(TOP)/mak/program.mak

tests:
