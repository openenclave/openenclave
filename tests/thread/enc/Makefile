include ../../../mak/defs.mak

CXXSHLIB = threadenc

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset

SOURCES = enc.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/openenclave/libc

LIBRARIES += -loelibc

include $(MAKDIR)/enclave.mak
