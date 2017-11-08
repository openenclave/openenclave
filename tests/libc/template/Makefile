include ../../../mak/defs.mak

SUPPRESS_WERROR=1

CSHLIB = libcenc

SOURCES += $(wildcard *.c)

SOURCES += $(TOP)/3rdparty/musl/libc-test/src/functional/tls_align_dso.c
SOURCES += $(TOP)/3rdparty/musl/libc-test/src/common/rand.c
SOURCES += $(TOP)/3rdparty/musl/libc-test/src/common/mtest.c

SIGNCONF = sign.conf

KEYFILE = private.pem

INCLUDES += -I$(INCDIR)/openenclave/libc
INCLUDES += -I$(TOP)/3rdparty/musl/libc-test/src/common

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak

RUNTEST=$(TOP)/tests/runtest/runtest

tests:
	$(RUNTEST) $(CSHLIB).signed.so

