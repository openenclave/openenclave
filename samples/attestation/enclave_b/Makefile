# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) genkey
	$(MAKE) -C ../enclave_a genkey
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
	../gen_pubkey_header.sh ../enclave_a/enclave_b_pubkey.h $<

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../attestation.edl --trusted --trusted-dir ../common \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I../../../include -I. -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/attestation_t.c
	$(CXX) -o enclave_b attestation.o crypto.o ecalls.o dispatcher.o attestation_t.o $(LDFLAGS)

sign:
	oesign sign -e enclave_b -c enc.conf -k private.pem

clean:
	rm -f *.o enclave_b enclave_b.signed ../common/attestation_t.* ../common/attestation_args.h *.pem enclave_a_pubkey.h
