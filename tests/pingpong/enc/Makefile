include ../../../mak/defs.mak

CXXSHLIB = pingpongenc

SOURCES = enc.cpp pingpong_t.c

SIGNCONF = sign.conf

KEYFILE = private.pem

include $(MAKDIR)/enclave.mak

gen:
	$(BINDIR)/oegen -t ../pingpong.idl

