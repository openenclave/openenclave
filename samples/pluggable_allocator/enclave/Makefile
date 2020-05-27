# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

ifeq ($(LVI_MITIGATION), ControlFlow)
	ifeq ($(LVI_MITIGATION_BINDIR),)
		$(error LVI_MITIGATION_BINDIR is not set)
	endif
	# Only run once.
	ifeq (,$(findstring $(LVI_MITIGATION_BINDIR),$(CC)))
		CC := $(LVI_MITIGATION_BINDIR)/$(CC)
	endif
	COMPILER := $(COMPILER)-lvi-cfg
endif

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
LDFLAGS_CUSTOM=$(subst -loelibc,-loesnmalloc -loelibc, $(LDFLAGS))
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../allocator_demo.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) -DOE_API_VERSION=2 enc.cpp -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 allocator_demo_t.c -o allocator_demo_t.o
	$(CC) -o enclave_default allocator_demo_t.o enc.o $(LDFLAGS) -loelibcxx -loelibc -loecore
	$(CC) -o enclave_custom allocator_demo_t.o enc.o $(LDFLAGS_CUSTOM) -loelibcxx -loelibc -loecore

sign:
	oesign sign -e enclave_default -c allocator_demo.conf -k private.pem
	oesign sign -e enclave_custom -c allocator_demo.conf -k private.pem

clean:
	rm -f enclave_default enclave_default.signed
	rm -f enclave_custom enclave_custom.signed
	rm -f private.pem public.pem
	rm -f enc.o allocator_demo_t.o
	rm -f allocator_demo_t.h allocator_demo_t.c allocator_demo_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
