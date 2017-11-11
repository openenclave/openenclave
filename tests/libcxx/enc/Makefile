include ../../../mak/defs.mak

CXXSHLIB = libcxxenc

SUPPRESS_WERROR=1

SOURCES += enc.cpp main.cpp fuzzing.cpp memory_resource.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

ifdef TEST
DEFINES += -D__TEST__=\"$(TEST)\"
else
DEFINES += -D__TEST__=\"test.cpp\"
endif
DEFINES += -DWITH_MAIN

INCLUDES += -I$(INCDIR)/openenclave/libcxx
INCLUDES += -I$(INCDIR)/openenclave/libc

INCLUDES += -I$(TOP)/tests/libcxx
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/test
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/test/support
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/fuzzing

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibcxx.a)
LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

LIBRARIES += -L$(LIBDIR)/enclave -loelibcxx -loelibc

include $(MAKDIR)/enclave.mak

ifeq ($(OE_SIMULATION), 1)
OPTS = --simulate
endif

tests:
	../host/libcxxhost $(OPTS) $(CXXSHLIB).signed.so

