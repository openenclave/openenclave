include ../../../mak/defs.mak

NEED_CXX=1

CXXSHLIB = stdcxxenc

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset
CFLAGS += -fno-builtin-fprintf
CFLAGS += -fno-builtin-printf

SOURCES = enc.cpp f.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/openenclave/libcxx
INCLUDES += -I$(INCDIR)/openenclave/libc

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibcxx.a)
LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak
