include ../../../mak/defs.mak

CXXSHLIB = SampleAppAttestation

SOURCES = SampleAppAttestation.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/enclave/libc

LIBRARIES += -L$(LIBDIR)/enclave -loelibc

NEED_LIBC=1
include $(MAKDIR)/enclave.mak
