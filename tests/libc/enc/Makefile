include ../../../mak/defs.mak

SUPPRESS_WERROR=1

CSHLIB = libcenc

SOURCES += enc.c mtest.c rand.c tls_align_dso.c main.c

SIGNCONF = sign.conf

KEYFILE = private.pem

ifdef TEST
DEFINES += -D__TEST__=\"$(TEST)\"
else
DEFINES += -D__TEST__=\"test.c\"
endif

INCLUDES += -I$(INCDIR)/openenclave/libc
INCLUDES += -I$(TOP)/3rdparty/musl/libc-test/src/common
INCLUDES += -I..

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

CLEAN = main.o

include $(MAKDIR)/enclave.mak

ifeq ($(OE_SIMULATION), 1)
OPTS = --simulate
endif

tests:
	../host/libchost $(OPTS) $(CSHLIB).signed.so

