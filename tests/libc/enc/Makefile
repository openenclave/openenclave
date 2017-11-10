include ../../../mak/defs.mak

SUPPRESS_WERROR=1

CSHLIB = libcenc

SOURCES += enc.c mtest.c rand.c test.c tls_align_dso.c

SIGNCONF = sign.conf

KEYFILE = private.pem

ifdef TEST
DEFINES += -D__TEST__=\"$(TEST)\"
else
DEFINES += -D__TEST__=\"test.c\"
endif

INCLUDES += -I$(INCDIR)/openenclave/libc
INCLUDES += -I$(TOP)/3rdparty/musl/libc-test/src/common

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak

tests:
	../host/libchost $(CSHLIB).signed.so

