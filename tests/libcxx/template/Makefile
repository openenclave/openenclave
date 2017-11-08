include ../../../mak/defs.mak

CXXSHLIB = libcxxenc

SUPPRESS_WERROR=1

SOURCES += enc.cpp 
SOURCES += main.cpp 
SOURCES += $(TOP)/3rdparty/libcxx/libcxx/fuzzing/fuzzing.cpp
SOURCES += $(TOP)/3rdparty/libcxx/libcxx/src/experimental/memory_resource.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

DEFINES = -DWITH_MAIN

INCLUDES += -I$(INCDIR)/openenclave/libcxx
INCLUDES += -I$(INCDIR)/openenclave/libc
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/test
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/test/support
INCLUDES += -I$(TOP)/3rdparty/libcxx/libcxx/fuzzing

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibcxx.a)
LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak

RUNTEST=$(TOP)/tests/runtest/runtest

tests:
	$(RUNTEST) $(CXXSHLIB).signed.so
