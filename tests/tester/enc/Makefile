include ../../../mak/defs.mak

CXXSHLIB = testerenc

INCLUDES += -I$(INCDIR)/openenclave/libc

LIBRARIES += -loeidl -loelibc

SOURCES = enc.cpp tester_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/openenclave/libc

LIBRARIES += -loelibc

include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/oegen -t ../tester.idl

