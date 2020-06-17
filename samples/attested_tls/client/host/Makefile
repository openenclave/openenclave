# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_client.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -c $(CFLAGS) $(CINCLUDES) tls_client_u.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o tls_client_host host.o tls_client_u.o $(LDFLAGS)

clean:
	rm -f tls_client_host host.o tls_client_u.* tls_client_args.h
