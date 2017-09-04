include ../../../mak/defs.mak

CXXSHLIB = testerenc

SOURCES = enc.cpp tester_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/enclave/libc

LIBRARIES += -L$(LIBDIR)/enclave -loelibc

include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/oegen -t ../tester.idl

