# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

.PHONY: all build clean run

SRC_FILES = ecalls.cpp mbedtls_client.cpp cert_verify_config.cpp ../../common/cert_verifier.cpp ../../common/identity_verifier.cpp ../../common/utility.cpp ../../common/mbedtls_utility.cpp
OBJ_FILES = ecalls.o mbedtls_client.o cert_verify_config.o cert_verifier.o identity_verifier.o utility.o mbedtls_utility.o tls_client_t.o

ifeq (${OE_CRYPTO_LIB}, openssl)
	SRC_FILES = ecalls.cpp openssl_client.cpp cert_verify_config.cpp ../../common/verify_callback.cpp ../../common/utility.cpp ../../common/openssl_utility.cpp
	OBJ_FILES = ecalls.o openssl_client.o cert_verify_config.o verify_callback.o utility.o openssl_utility.o tls_client_t.o
endif

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_client.edl --trusted --trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx

	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I. -std=c++11 $(SRC_FILES)
	$(CC) -c $(CFLAGS) $(CINCLUDES) -I. ./tls_client_t.c
	$(CXX) -o tls_client_enc $(OBJ_FILES) $(LDFLAGS) $(CRYPTO_LDFLAGS) -loehostsock -loehostresolver

sign:
	oesign sign -e tls_client_enc -c  enc.conf -k private.pem

clean:
	rm -f ./*.o tls_client_enc tls_client_enc.signed enclave1.signed.so tls_client_t.* tls_client_args.h
