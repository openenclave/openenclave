# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

ifneq (,$(findstring openssl_3,$(OE_CRYPTO_LIB)))
	CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=openssl_3flags)
	CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --variable=openssl_3flags)
else
	CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
	CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
endif
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

.PHONY: all build clean run

SRC_FILES = ecalls.cpp mbedtls_server.cpp cert_verify_config.cpp ../../common/identity_verifier.cpp ../../common/cert_verifier.cpp ../../common/utility.cpp ../../common/mbedtls_utility.cpp
OBJ_FILES = ecalls.o mbedtls_server.o cert_verify_config.o cert_verifier.o identity_verifier.o utility.o mbedtls_utility.o tls_server_t.o

# Cover openssl, openssl_3, openssl_symcrypt_fips, openssl_3_symcrypt_prov_fips
ifneq (,$(findstring openssl,$(OE_CRYPTO_LIB)))
	SRC_FILES = ecalls.cpp openssl_server.cpp cert_verify_config.cpp ../../common/verify_callback.cpp ../../common/utility.cpp ../../common/openssl_utility.cpp
	OBJ_FILES = ecalls.o openssl_server.o cert_verify_config.o verify_callback.o utility.o openssl_utility.o tls_server_t.o
endif

EDL_USE_HOST_ENTROPY =

ifneq (,$(findstring symcrypt,$(OE_CRYPTO_LIB)))
	OBJ_FILES += libsymcrypt.so.103
	EDL_USE_HOST_ENTROPY = -DEDL_USE_HOST_ENTROPY
endif

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted \
		--trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx \
		$(EDL_USE_HOST_ENTROPY)


	$(CXX) -g -c $(CXXFLAGS) -I. -std=c++11 ${SRC_FILES}
	$(CC) -c $(CFLAGS) -I. tls_server_t.c
	$(CXX) -o tls_server_enc $(OBJ_FILES) $(LDFLAGS) $(CRYPTO_LDFLAGS) -loehostsock -loehostresolver

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem
	oesign dump -e tls_server_enc.signed > temp.dmp
	chmod u+x ../../scripts/gen_mrenclave_header.sh
	../../scripts/gen_mrenclave_header.sh ../../common/tls_server_enc_mrenclave.h temp.dmp
	rm temp.dmp

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h yy ../../common/tls_server_enc_mrenclave.h
