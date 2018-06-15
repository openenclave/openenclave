# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CXXFLAGS = -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++

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
LDFLAGS += -Wl,-eoe_main 

# Ensure attestation functionality in enclave.
LDFLAGS += -Wl,--undefined=__liboecore

# Order of libraries below matters.
LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave -loelibcxx -loeenclave -lmbedcrypto -lmbedtls -lmbedx509 -loelibc -loecore

all:
	$(MAKE) build
	$(MAKE) sign

build:
	g++ -g -c $(CXXFLAGS) $(INCLUDES) attestation.cpp crypto.cpp ecalls.cpp init.cpp
	g++ -o attestation_enc.so attestation.o crypto.o ecalls.o init.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign attestation_enc.so enc.conf private.pem

clean:
	rm -f enc.o attestation_enc.so attestation_enc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
