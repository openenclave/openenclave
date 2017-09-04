include ../../../mak/defs.mak

CSHLIB = mbedenc

SOURCES = enc.c

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/enclave/libc

LIBRARIES += $(call whole-archive, $(LIBDIR)/enclave/libmbedcrypto.a)

LIBRARIES += $(call whole-archive, $(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak
