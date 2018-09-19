# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CC=clang-7

CFLAGS=$(shell pkg-config oehost-clang --cflags)

LDFLAGS=$(shell pkg-config oehost-clang --libs)

all: build

build:
	$(CC) -c $(CFLAGS) host.c
	$(CC) -o helloworldhost host.o $(LDFLAGS)

clean:
	rm -f helloworldhost host.o

