# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CXX = clang++-7

CXXFLAGS += -Wall -Werror -O2 -m64 -nostdinc -fPIC -std=c++11 -nostdinc++
CXXFLAGS += -mllvm -x86-speculative-load-hardening

INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie

LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
LIBRARIES += -loeenclave
LIBRARIES += -loelibcxx
LIBRARIES += -lmbedx509 
LIBRARIES += -lmbedcrypto 
LIBRARIES += -loelibc
LIBRARIES += -loecore

all:
	$(MAKE) build
	$(MAKE) sign

build:
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) enc.cpp -o enc.o
	$(CXX) -o sortenc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign sortenc.so sort.conf private.pem

clean:
	rm -f enc.o sortenc.so sortenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
