include ../../../mak/defs.mak

CXXSHLIB = fileenc

SOURCES = enc.cpp file_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/oegen -t ../file.idl

