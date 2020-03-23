# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../switchless.edl --trusted
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 enc.c -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 switchless_t.c -o switchless_t.o
	$(CC) -o switchlessenc switchless_t.o enc.o $(LDFLAGS)

sign:
	oesign sign -e switchlessenc -c switchless.conf -k private.pem

clean:
	rm -f enc.o switchlessenc switchlessenc.signed private.pem public.pem switchless_t.o switchless_t.h switchless_t.c switchless_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
