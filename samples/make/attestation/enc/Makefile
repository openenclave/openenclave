# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CXX = clang++-7

CXXFLAGS += -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++
CXXFLAGS += -mllvm -x86-speculative-load-hardening

# To include Open Enclave SDK headers and
# Open Enclave compatible mbedtls headers.
INCLUDES += -I$(OE_INCLUDEDIR)

#  To use Open Enclave compatible C and C++ standard libraries.
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

OE_LIBS1 =  -Wl,--start-group -Wl,--whole-archive -loeenclave -loecore -Wl,--end-group
OE_LIBS2 =  -loelibcxx -loelibc -lmbedtls -lmbedx509 -lmbedcrypto

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave ${OE_LIBS1} ${OE_LIBS2}

all:
	$(MAKE) build
	$(MAKE) sign

build:
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) attestation.cpp crypto.cpp ecalls.cpp init.cpp
	$(CXX) -o attestation_enc.so attestation.o crypto.o ecalls.o init.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign attestation_enc.so enc.conf private.pem

clean:
	rm -f enc.o attestation_enc.so attestation_enc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
