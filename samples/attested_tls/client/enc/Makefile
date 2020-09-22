# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)

.PHONY: all build clean run

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

ifeq (${OE_CRYPTO_LIB}, mbedtls)
	SRC_FILES := ecalls.cpp ${OE_CRYPTO_LIB}/client.cpp ${OE_CRYPTO_LIB}/identity_verifier.cpp ${OE_CRYPTO_LIB}/cert_verifier.cpp ../../common/utility.cpp
	OBJ_FILES := ecalls.o client.o cert_verifier.o identity_verifier.o utility.o tls_client_t.o
	ADDITIONAL_LDFLAGS :=
endif

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_client.edl --trusted --trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ${SRC_FILES}
	$(CC) -c $(CFLAGS) $(CINCLUDES) ./tls_client_t.c
	$(CXX) -o tls_client_enclave ${OBJ_FILES} $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore ${ADDITIONAL_LDFLAGS} -loelibc -loesyscall

sign:
	oesign sign -e tls_client_enclave -c  enc.conf -k private.pem

clean:
	rm -f ./*.o tls_client_enclave tls_client_enclave.signed enclave1.signed.so tls_client_t.* tls_client_args.h
