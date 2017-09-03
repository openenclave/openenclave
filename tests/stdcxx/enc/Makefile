include ../../../mak/defs.mak

NEED_CXX=1

CXXSHLIB = stdcxxenc

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset
CFLAGS += -fno-builtin-fprintf
CFLAGS += -fno-builtin-printf

SOURCES = enc.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

WHOLE_ARCHIVE=1
NEED_LIBCXX=1
include $(MAKDIR)/enclave.mak
