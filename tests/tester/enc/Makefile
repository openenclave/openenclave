include ../../../mak/defs.mak

CXXSHLIB = testerenc

SOURCES = enc.cpp tester_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/encgen -t ../tester.idl

