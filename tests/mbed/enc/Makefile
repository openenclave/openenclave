include ../../../mak/defs.mak

CSHLIB = mbedenc

SOURCES = enc.c

SIGNCONF = sign.conf

KEYFILE = private.pem

EXTRA_LDFLAGS += $(call whole-archive, $(LIBDIR)/enclave/libmbedcrypto.a)

EXTRA_LDFLAGS += $(LIBDIR)/enclave/liboelibc.a

NEED_LIBC=1
include $(MAKDIR)/enclave.mak
