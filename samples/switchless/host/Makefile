# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../switchless.edl --untrusted
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) switchless_u.c
	$(CC) -o switchlesshost switchless_u.o host.o $(LDFLAGS)

clean:
	rm -f switchlesshost host.o switchless_u.o switchless_u.c switchless_u.h switchless_args.h
