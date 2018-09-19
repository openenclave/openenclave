# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

USE_CLANG=1

ifdef USE_CLANG
CC=clang-7
COMPILER=clang
else
CC=gcc
COMPILER=gcc
endif

ENCLAVE_CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
ENCLAVE_LIBS=$(shell pkg-config oeenclave-$(COMPILER) --libs)

HOST_CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
HOST_LIBS=$(shell pkg-config oehost-$(COMPILER) --libs)

all: build_enclave build_host

build_enclave:
	$(CC) $(ENCLAVE_CFLAGS) -o enc enc.c $(ENCLAVE_LIBS)

build_host:
	$(CC) $(HOST_CFLAGS) -o host host.c $(HOST_LIBS)

run:
	./host enc

clean:
	rm -rf enc host
