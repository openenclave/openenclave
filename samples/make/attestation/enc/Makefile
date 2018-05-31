# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include $(OPENENCLAVE_CONFIG)

CXXFLAGS = -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++

INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,-eOE_Main 

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave  -Wl,--start-group -loelibcxx -loeenclave -lmbedcrypto -lmbedtls -lmbedx509 -loelibc -loecore -Wl,--end-group

all:
	$(MAKE) build
	$(MAKE) sign

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) enc.cpp -o enc.o
	g++ -o attestation_enc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign attestation_enc.so enc.conf private.pem

clean:
	rm -f enc.o attestation_enc.so attestation_enc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
