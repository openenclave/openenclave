# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) genkey
	$(MAKE) -C ../enc1 genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

# The enclaves in the sample will check if the other enclave is signed
# with the expected key. Since this sample builds both enclaves, we can
# inject the expected public keys at build time.
#
# If the other public key isn't known, then we would have to load the
# public key from the host. We can't simply load the raw public key since
# a malicious host might change it. So, we would need to load a certicate
# that contains the expected public key that is signed by a trusted CA.
genkey: public.pem
	../gen_pubkey_header.sh ../enc1/enc2_pubkey.h $<

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/remoteattestation_t.c
	$(CXX) -o enclave2 attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o $(LDFLAGS) 

sign:
	oesign sign enclave2 enc.conf private.pem

clean:
	rm -f *.o enclave2 enclave2.signed remoteattestation_t.* *.pem enc1_pubkey.h



