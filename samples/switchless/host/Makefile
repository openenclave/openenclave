# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../switchless_sample.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) switchless_sample_u.c
	$(CC) -o switchlesshost switchless_sample_u.o host.o $(LDFLAGS)

clean:
	rm -f switchlesshost host.o switchless_sample_u.o \
		switchless_sample_u.c switchless_u.h switchless_args.h
