include ../../../mak/defs.mak

NEED_CXX=1

CXXSHLIB = testenc

SOURCES += enc.cpp main.cpp

SIGNCONF = sign.conf

KEYFILE = private.pem

DEFINES = -DWITH_MAIN

LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibcxx.a)
LIBRARIES += $(call whole-archive,$(LIBDIR)/enclave/liboelibc.a)

include $(MAKDIR)/enclave.mak
