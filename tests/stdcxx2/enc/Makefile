NEED_RTTI=1
NEED_EXCEPTIONS=1
NO_ENCCXX=1
include ../../../mak/defs.mak

CXXSHLIB = stdcxxenc

INCLUDES += -I$(INCDIR)/llvm -I$(INCDIR)/pthread

CFLAGS += -fno-builtin-strcpy
CFLAGS += -fno-builtin-strcat
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset

#EXTRA_LDFLAGS += $(LIBDIR)/libcxxrt.a
#EXTRA_LDFLAGS += $(LIBDIR)/libunwind.a

EXTRA_LDFLAGS += -L$(LIBDIR)
EXTRA_LDFLAGS += -lcxxrt
EXTRA_LDFLAGS += -lunwind
EXTRA_LDFLAGS += -lc

SOURCES = enc.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

include $(MAKDIR)/enclave.mak
