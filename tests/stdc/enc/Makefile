include ../../../mak/defs.mak

CXXSHLIB = stdcenc

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset

SOURCES=enc.cpp

SIGNCONF=sign.conf

KEYFILE=private.pem

INCLUDES+=-I$(INCDIR)/enclave/libc

LIBRARIES+=$(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak
