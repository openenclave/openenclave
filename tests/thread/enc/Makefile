include ../../../mak/defs.mak

CXXSHLIB = threadenc

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset

SOURCES = enc.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/enclave/libc

LIBRARIES += -L$(LIBDIR)/enclave -loelibc

include $(MAKDIR)/enclave.mak
