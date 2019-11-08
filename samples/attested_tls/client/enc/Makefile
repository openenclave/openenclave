# Copyright (c) Open Enclave SDK contributors.
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

.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_client.edl --trusted --trusted-dir .
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ecalls.cpp client.cpp cert_verifier.cpp identity_verifier.cpp ../../common/utility.cpp crypto.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ./tls_client_t.c
	$(CXX) -o tls_client_enclave ecalls.o crypto.o client.o cert_verifier.o identity_verifier.o utility.o tls_client_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tls_client_enclave -c  enc.conf -k private.pem

clean:
	rm -f ./*.o tls_client_enclave tls_client_enclave.signed enclave1.signed.so tls_client_t.* tls_client_args.h
