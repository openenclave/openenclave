# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../allocator_demo.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) host.cpp
	$(CC) -g -c $(CFLAGS) allocator_demo_u.c
	$(CXX) -o allocator_demo_host allocator_demo_u.o host.o $(LDFLAGS)

clean:
	rm -f allocator_demo_host host.o allocator_demo_u.o allocator_demo_u.c allocator_demo_u.h allocator_demo_args.h
