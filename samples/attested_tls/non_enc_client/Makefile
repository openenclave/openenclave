# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

.PHONY: all build clean run

all: build

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I/usr/include/openssl client.cpp verify_callback.cpp verify_signer_openssl.cpp
	$(CXX) -o tls_non_enc_client client.o verify_callback.o verify_signer_openssl.o $(LDFLAGS)

clean:
	rm -f tls_non_enc_client *.o ../cert.der

run:
	./tls_non_enc_client -server:localhost -port:12341
