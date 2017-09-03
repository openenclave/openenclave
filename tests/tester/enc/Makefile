include ../../../mak/defs.mak

CXXSHLIB = testerenc

SOURCES = enc.cpp tester_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

NEED_LIBC=1
include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/oegen -t ../tester.idl

