# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../switchless_sample.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 enc.c -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 switchless_sample_t.c -o switchless_sample_t.o
	$(CC) -o switchlessenc switchless_sample_t.o enc.o $(LDFLAGS)

sign:
	oesign sign -e switchlessenc -c switchless.conf -k private.pem

clean:
	rm -f enc.o switchlessenc switchlessenc.signed private.pem public.pem \
		switchless_sample_t.o switchless_sample_t.h switchless_sample_t.c \
		switchless_sample_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
