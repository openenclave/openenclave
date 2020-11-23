# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

.PHONY: all build clean run

SRC_FILES = -DSERVER_CERT_VERIFY_CALLBACK  ecalls.cpp mbedtls_server.cpp ../../common/identity_verifier.cpp ../../common/cert_verifier.cpp ../../common/utility.cpp ../../common/mbedtls_utility.cpp
OBJ_FILES = ecalls.o mbedtls_server.o cert_verifier.o identity_verifier.o utility.o mbedtls_utility.o tls_server_t.o
ifeq (${OE_CRYPTO_LIB}, openssl)
	SRC_FILES = ecalls.cpp openssl_server.cpp ../../common/utility.cpp ../../common/openssl_utility.cpp
	OBJ_FILES = ecalls.o openssl_server.o utility.o openssl_utility.o tls_server_t.o
endif

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted \
		--trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx


	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ${SRC_FILES}
	$(CC) -c $(CFLAGS) $(CINCLUDES) tls_server_t.c
	$(CXX) -o tls_server_enc $(OBJ_FILES) $(LDFLAGS) $(CRYPTO_LDFLAGS) -loehostsock -loehostresolver

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem
	oesign dump -e tls_server_enc.signed > temp.dmp
	chmod u+x ../../scripts/gen_mrenclave_header.sh
	../../scripts/gen_mrenclave_header.sh ../../common/tls_server_enc_mrenclave.h temp.dmp
	rm temp.dmp

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h yy ../../common/tls_server_enc_mrenclave.h
