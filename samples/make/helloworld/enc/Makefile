# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CC=clang-7

CFLAGS=$(shell pkg-config oeenclave-clang --cflags)

LDFLAGS=$(shell pkg-config oeenclave-clang --libs)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	$(CC) -c $(CFLAGS) enc.c -o enc.o
	$(CC) -o helloworldenc.so enc.o $(LDFLAGS)

sign:
	$(OE_BINDIR)/oesign helloworldenc.so helloworld.conf private.pem

clean:
	rm -f enc.o helloworldenc.so hellowworldenc.signed.so private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
