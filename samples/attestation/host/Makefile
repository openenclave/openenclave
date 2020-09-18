# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../attestation.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) attestation_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 host.cpp
	$(CXX) -o attestation_host host.o attestation_u.o $(LDFLAGS)

clean:
	rm -f attestation_host *.o attestation_u.*  attestation_args.h
