# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build


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

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I/usr/include/openssl client.cpp identity_verifier.cpp verify_signer_openssl.cpp
	$(CXX) -o tls_non_enc_client client.o identity_verifier.o verify_signer_openssl.o $(LDFLAGS)

clean:
	rm -f tls_client *.o ../cert.der

run:
	./tls_non_enc_client -server:localhost -port:12341
