include ../../../mak/defs.mak

CXXSHLIB = SampleAppCRT

SOURCES = SampleAppCRT.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/enclave/libc

LIBRARIES += $(LIBDIR)/enclave/liboelibc.a

NEED_LIBC=1
include $(MAKDIR)/enclave.mak
