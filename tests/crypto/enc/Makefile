include ../../../mak/defs.mak

CXXSHLIB = cryptoenc

SOURCES = enc.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

CRYPTOLIB=$(LIBDIR)/enclave/libcrypto.a

NEED_ECRYPTO=1
include $(MAKDIR)/enclave.mak
